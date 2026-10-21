#define _GNU_SOURCE
#include <gtk/gtk.h>
#include <gdk/gdkx.h>
#include <lightdm.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <X11/XKBlib.h>

#define RECENT "/var/lib/shared-workspace/recent-users"
#define CURRENT "/run/shared-workspace/current"

static LightDMGreeter *greeter;
static GtkWidget *window, *users_box, *username_entry, *password_entry;
static GtkWidget *username_label, *password_label, *status_label;
static GtkWidget *login_button, *back_button, *layout_button;
static gchar *selected_user, *pending_password;
static gboolean response_used;

static gboolean valid_name(const char *s) {
    if (!s || !*s || strlen(s) >= 128) return FALSE;
    for (; *s; ++s)
        if (!(g_ascii_islower(*s) || g_ascii_isdigit(*s) || *s == '-' || *s == '_' || *s == '.' || *s == '@'))
            return FALSE;
    return TRUE;
}

static gchar *display_name(const char *user) {
    struct passwd *p = getpwnam(user);
    if (p && p->pw_gecos && *p->pw_gecos) {
        gchar **parts = g_strsplit(p->pw_gecos, ",", 2);
        gchar *result = g_strdup(parts[0]);
        g_strfreev(parts);
        if (*result) return result;
        g_free(result);
    }
    return g_strdup(user);
}

static gchar *current_employee(void) {
    gchar *contents = NULL;
    if (!g_file_get_contents(CURRENT, &contents, NULL, NULL)) return NULL;
    gchar **lines = g_strsplit(contents, "\n", -1), *result = NULL;
    for (int i = 0; lines[i]; i++)
        if (g_str_has_prefix(lines[i], "employee=") && valid_name(lines[i] + 9)) {
            result = g_strdup(lines[i] + 9); break;
        }
    g_strfreev(lines); g_free(contents); return result;
}

static void set_status(const char *text, gboolean error) {
    gchar *escaped = g_markup_escape_text(text ? text : "", -1);
    gchar *markup = g_strdup_printf("<span foreground='%s'>%s</span>", error ? "#ff8a80" : "#d0d7de", escaped);
    gtk_label_set_markup(GTK_LABEL(status_label), markup);
    g_free(markup); g_free(escaped);
}

static void clear_secret(void) {
    if (pending_password) {
        explicit_bzero(pending_password, strlen(pending_password));
        g_clear_pointer(&pending_password, g_free);
    }
    gtk_entry_set_text(GTK_ENTRY(password_entry), "");
}

static void show_users(void) {
    clear_secret();
    g_clear_pointer(&selected_user, g_free);
    gtk_widget_show(users_box);
    gtk_widget_hide(username_entry);
    gtk_widget_hide(username_label);
    gtk_widget_hide(password_label);
    gtk_widget_hide(password_entry);
    gtk_widget_hide(login_button);
    gtk_widget_hide(back_button);
    set_status("Выбери пользователя", FALSE);
}

static void choose_user(const char *user, gboolean other) {
    clear_secret();
    g_clear_pointer(&selected_user, g_free);
    if (!other) selected_user = g_strdup(user);
    gtk_widget_hide(users_box);
    gtk_widget_set_visible(username_entry, other);
    gtk_widget_show(username_label);
    gtk_widget_show(password_label);
    gtk_widget_show(password_entry);
    gtk_widget_show(login_button);
    gtk_widget_show(back_button);
    if (other) {
        gtk_label_set_text(GTK_LABEL(username_label), "Логин");
        gtk_entry_set_text(GTK_ENTRY(username_entry), "");
        gtk_widget_grab_focus(username_entry);
        set_status("Введи доменный логин и пароль", FALSE);
    } else {
        gchar *name = display_name(user);
        gchar *login = g_strdup_printf("Логин: %s", user);
        gchar *message = g_strdup_printf("Вход: %s", name);
        gtk_label_set_text(GTK_LABEL(username_label), login);
        set_status(message, FALSE);
        g_free(login); g_free(message); g_free(name);
        gtk_widget_grab_focus(password_entry);
    }
}

static void user_clicked(GtkButton *button, gpointer data) {
    (void)button;
    choose_user((const char *)data, FALSE);
}

static void other_clicked(GtkButton *button, gpointer data) {
    (void)button; (void)data; choose_user(NULL, TRUE);
}

static void begin_login(void) {
    const char *user = selected_user;
    if (!user) user = gtk_entry_get_text(GTK_ENTRY(username_entry));
    const char *password = gtk_entry_get_text(GTK_ENTRY(password_entry));
    if (!valid_name(user) || !password || !*password) {
        set_status("Укажи логин и пароль", TRUE); return;
    }
    gchar *user_copy = g_strdup(user);
    gchar *password_copy = g_strdup(password);
    g_clear_pointer(&selected_user, g_free);
    selected_user = user_copy;
    clear_secret();
    pending_password = password_copy;
    if (!pending_password || !*pending_password) {
        set_status("Укажи пароль", TRUE); return;
    }
    response_used = FALSE;
    gtk_widget_set_sensitive(login_button, FALSE);
    gtk_widget_set_sensitive(back_button, FALSE);
    set_status("Проверяю доменную учётную запись…", FALSE);
    GError *error = NULL;
    if (!lightdm_greeter_authenticate(greeter, selected_user, &error)) {
        set_status(error ? error->message : "Не удалось начать проверку", TRUE);
        g_clear_error(&error);
        gtk_widget_set_sensitive(login_button, TRUE);
        gtk_widget_set_sensitive(back_button, TRUE);
        clear_secret();
    }
}

static void free_signal_data(gpointer data, GClosure *closure) { (void)closure; g_free(data); }

static void login_clicked(GtkButton *button, gpointer data) { (void)button; (void)data; begin_login(); }
static void password_activate(GtkEntry *entry, gpointer data) { (void)entry; (void)data; begin_login(); }
static void back_clicked(GtkButton *button, gpointer data) { (void)button; (void)data; show_users(); }

static void show_prompt(LightDMGreeter *g, const gchar *text, LightDMPromptType type, gpointer data) {
    (void)data;
    const char *reply = "";
    if (type == LIGHTDM_PROMPT_TYPE_SECRET) {
        if (!response_used && pending_password) { reply = pending_password; response_used = TRUE; }
    } else if (selected_user) reply = selected_user;
    GError *error = NULL;
    if (!lightdm_greeter_respond(g, reply, &error)) {
        set_status(error ? error->message : text, TRUE);
        g_clear_error(&error);
    }
}

static void show_message(LightDMGreeter *g, const gchar *text, LightDMMessageType type, gpointer data) {
    (void)g; (void)data;
    /* Do not replace the useful progress message with an empty PAM message. */
    if (text && *text) set_status(text, type == LIGHTDM_MESSAGE_TYPE_ERROR);
}

static void authentication_complete(LightDMGreeter *g, gpointer data) {
    (void)data;
    clear_secret();
    if (lightdm_greeter_get_is_authenticated(g)) {
        set_status("Открываю общее рабочее место…", FALSE);
        GError *error = NULL;
        if (lightdm_greeter_start_session_sync(g, NULL, &error)) return;
        set_status(error ? error->message : "Не удалось открыть рабочее место", TRUE);
        g_clear_error(&error);
    } else set_status("Неверный пароль или доступ к этому компьютеру запрещён", TRUE);
    gtk_widget_set_sensitive(login_button, TRUE);
    gtk_widget_set_sensitive(back_button, TRUE);
    gtk_widget_grab_focus(password_entry);
}

static void add_user_button(const char *user) {
    gchar *name = display_name(user);
    gchar *label = g_strdup_printf("%s\n%s", name, user);
    GtkWidget *button = gtk_button_new_with_label(label);
    gtk_widget_set_size_request(button, 190, 72);
    gtk_style_context_add_class(gtk_widget_get_style_context(button), "user-button");
    g_signal_connect_data(button, "clicked", G_CALLBACK(user_clicked), g_strdup(user), free_signal_data, 0);
    gtk_box_pack_start(GTK_BOX(users_box), button, FALSE, FALSE, 6);
    g_free(label); g_free(name);
}

static void load_users(void) {
    gchar *current = current_employee();
    if (current) add_user_button(current);
    gchar *contents = NULL;
    if (g_file_get_contents(RECENT, &contents, NULL, NULL)) {
        gchar **lines = g_strsplit(contents, "\n", -1);
        int shown = current ? 1 : 0;
        for (int i = 0; lines[i] && shown < 8; i++)
            if (valid_name(lines[i]) && (!current || strcmp(lines[i], current))) {
                add_user_button(lines[i]); shown++;
            }
        g_strfreev(lines); g_free(contents);
    }
    GtkWidget *other = gtk_button_new_with_label("Другой пользователь");
    gtk_widget_set_size_request(other, 190, 52);
    g_signal_connect(other, "clicked", G_CALLBACK(other_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(users_box), other, FALSE, FALSE, 6);
    g_free(current);
}

static void power_clicked(GtkButton *button, gpointer data) {
    (void)button;
    gboolean restart = GPOINTER_TO_INT(data);
    const char *action = restart ? "Перезагрузить компьютер?" : "Выключить компьютер?";
    GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(window), GTK_DIALOG_MODAL,
                                               GTK_MESSAGE_QUESTION, GTK_BUTTONS_NONE,
                                               "%s", action);
    gtk_dialog_add_buttons(GTK_DIALOG(dialog), "Отмена", GTK_RESPONSE_CANCEL,
                           restart ? "Перезагрузить" : "Выключить", GTK_RESPONSE_ACCEPT,
                           NULL);
    gint response = gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
    if (response != GTK_RESPONSE_ACCEPT) return;
    GError *error = NULL;
    gboolean ok = restart ? lightdm_restart(&error) : lightdm_shutdown(&error);
    if (!ok) { set_status(error ? error->message : "Команда недоступна", TRUE); g_clear_error(&error); }
}

static unsigned keyboard_group(void) {
    GdkDisplay *gdk_display = gdk_display_get_default();
    if (!gdk_display || !GDK_IS_X11_DISPLAY(gdk_display)) return 0;
    XkbStateRec state;
    Display *display = GDK_DISPLAY_XDISPLAY(gdk_display);
    return XkbGetState(display, XkbUseCoreKbd, &state) == Success ? state.group : 0;
}

static void update_layout(void) {
    gtk_button_set_label(GTK_BUTTON(layout_button),
                         keyboard_group() == 1 ? "Раскладка: RU" : "Раскладка: EN");
}

static gboolean poll_layout(gpointer data) {
    (void)data; update_layout(); return G_SOURCE_CONTINUE;
}

static void layout_clicked(GtkButton *button, gpointer data) {
    (void)button; (void)data;
    GdkDisplay *gdk_display = gdk_display_get_default();
    if (!gdk_display || !GDK_IS_X11_DISPLAY(gdk_display)) return;
    Display *display = GDK_DISPLAY_XDISPLAY(gdk_display);
    XkbLockGroup(display, XkbUseCoreKbd, keyboard_group() == 1 ? 0 : 1);
    XFlush(display);
    update_layout();
}

static void apply_css(void) {
    const char *css =
        "window { background: #18212b; color: #f5f7fa; }"
        "entry { font-size: 18px; padding: 10px; min-width: 330px; }"
        "button { font-size: 16px; padding: 8px 16px; }"
        ".field-label { font-size: 15px; font-weight: bold; }"
        ".layout-button { font-size: 15px; padding: 6px 12px; }"
        ".user-button { font-size: 17px; }"
        ".title { font-size: 31px; font-weight: bold; }"
        ".status { font-size: 17px; }";
    GtkCssProvider *provider = gtk_css_provider_new();
    gtk_css_provider_load_from_data(provider, css, -1, NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(), GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(provider);
}

int main(int argc, char **argv) {
    gtk_init(&argc, &argv); apply_css();
    greeter = lightdm_greeter_new();
    g_signal_connect(greeter, "show-prompt", G_CALLBACK(show_prompt), NULL);
    g_signal_connect(greeter, "show-message", G_CALLBACK(show_message), NULL);
    g_signal_connect(greeter, "authentication-complete", G_CALLBACK(authentication_complete), NULL);
    GError *error = NULL;
    if (!lightdm_greeter_connect_to_daemon_sync(greeter, &error)) {
        g_printerr("LightDM connection failed: %s\n", error ? error->message : "unknown error"); return 1;
    }

    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    GdkDisplay *display = gdk_display_get_default();
    GdkMonitor *monitor = gdk_display_get_primary_monitor(display);
    if (!monitor)
        monitor = gdk_display_get_monitor(display, 0);
    GdkRectangle geometry = {0, 0, 1024, 768};
    if (monitor)
        gdk_monitor_get_geometry(monitor, &geometry);
    gtk_window_set_decorated(GTK_WINDOW(window), FALSE);
    gtk_window_set_resizable(GTK_WINDOW(window), TRUE);
    gtk_window_move(GTK_WINDOW(window), geometry.x, geometry.y);
    gtk_window_set_default_size(GTK_WINDOW(window), geometry.width, geometry.height);
    gtk_widget_set_size_request(window, geometry.width, geometry.height);
    gtk_window_fullscreen(GTK_WINDOW(window));
    gtk_window_set_title(GTK_WINDOW(window), "Office sign in");
    GtkWidget *center = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_halign(center, GTK_ALIGN_CENTER); gtk_widget_set_valign(center, GTK_ALIGN_CENTER);
    gtk_container_add(GTK_CONTAINER(window), center);
    GtkWidget *title = gtk_label_new("Общее рабочее место");
    gtk_style_context_add_class(gtk_widget_get_style_context(title), "title");
    gtk_box_pack_start(GTK_BOX(center), title, FALSE, FALSE, 12);
    layout_button = gtk_button_new_with_label("Раскладка: EN");
    gtk_widget_set_tooltip_text(layout_button, "Нажми для переключения EN/RU. Также работает Alt+Shift.");
    gtk_style_context_add_class(gtk_widget_get_style_context(layout_button), "layout-button");
    g_signal_connect(layout_button, "clicked", G_CALLBACK(layout_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(center), layout_button, FALSE, FALSE, 2);
    gchar *current = current_employee();
    if (current) {
        gchar *name = display_name(current), *text = g_strdup_printf("Сейчас работает: %s", name);
        GtkWidget *active = gtk_label_new(text); gtk_box_pack_start(GTK_BOX(center), active, FALSE, FALSE, 2);
        g_free(text); g_free(name); g_free(current);
    }
    users_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_box_pack_start(GTK_BOX(center), users_box, FALSE, FALSE, 4); load_users();
    username_label = gtk_label_new("Логин");
    gtk_widget_set_halign(username_label, GTK_ALIGN_START);
    gtk_style_context_add_class(gtk_widget_get_style_context(username_label), "field-label");
    username_entry = gtk_entry_new(); gtk_entry_set_placeholder_text(GTK_ENTRY(username_entry), "например, test");
    password_label = gtk_label_new("Пароль");
    gtk_widget_set_halign(password_label, GTK_ALIGN_START);
    gtk_style_context_add_class(gtk_widget_get_style_context(password_label), "field-label");
    password_entry = gtk_entry_new(); gtk_entry_set_visibility(GTK_ENTRY(password_entry), FALSE);
    gtk_entry_set_placeholder_text(GTK_ENTRY(password_entry), "Введи доменный пароль");
    g_signal_connect(password_entry, "activate", G_CALLBACK(password_activate), NULL);
    gtk_box_pack_start(GTK_BOX(center), username_label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(center), username_entry, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(center), password_label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(center), password_entry, FALSE, FALSE, 0);
    GtkWidget *actions = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    back_button = gtk_button_new_with_label("Назад"); login_button = gtk_button_new_with_label("Войти");
    g_signal_connect(back_button, "clicked", G_CALLBACK(back_clicked), NULL);
    g_signal_connect(login_button, "clicked", G_CALLBACK(login_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(actions), back_button, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(actions), login_button, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(center), actions, FALSE, FALSE, 2);
    status_label = gtk_label_new(""); gtk_label_set_line_wrap(GTK_LABEL(status_label), TRUE);
    gtk_style_context_add_class(gtk_widget_get_style_context(status_label), "status");
    gtk_box_pack_start(GTK_BOX(center), status_label, FALSE, FALSE, 8);
    GtkWidget *power = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    if (lightdm_get_can_restart()) {
        GtkWidget *b = gtk_button_new_with_label("Перезагрузить");
        g_signal_connect(b, "clicked", G_CALLBACK(power_clicked), GINT_TO_POINTER(1));
        gtk_box_pack_start(GTK_BOX(power), b, TRUE, TRUE, 0);
    }
    if (lightdm_get_can_shutdown()) {
        GtkWidget *b = gtk_button_new_with_label("Выключить");
        g_signal_connect(b, "clicked", G_CALLBACK(power_clicked), GINT_TO_POINTER(0));
        gtk_box_pack_start(GTK_BOX(power), b, TRUE, TRUE, 0);
    }
    gtk_box_pack_start(GTK_BOX(center), power, FALSE, FALSE, 16);
    gtk_widget_show_all(window); show_users();
    gtk_widget_realize(window);
    GdkCursor *cursor = gdk_cursor_new_from_name(display, "default");
    if (!cursor) cursor = gdk_cursor_new_from_name(display, "left_ptr");
    if (cursor) {
        gdk_window_set_cursor(gtk_widget_get_window(window), cursor);
        g_object_unref(cursor);
    }
    update_layout();
    g_timeout_add(250, poll_layout, NULL);
    gtk_window_maximize(GTK_WINDOW(window));
    gtk_main(); return 0;
}
