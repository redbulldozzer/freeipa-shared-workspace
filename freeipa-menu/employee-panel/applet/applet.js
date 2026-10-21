const Applet = imports.ui.applet;
const PopupMenu = imports.ui.popupMenu;
const Gio = imports.gi.Gio;
const Mainloop = imports.mainloop;
const HELPER = '/usr/local/libexec/office-employee-panel';

class EmployeeApplet extends Applet.TextApplet {
    constructor(orientation, height, id) {
        super(orientation, height, id);
        this.setAllowedLayout(Applet.AllowedLayout.BOTH);
        this._removed = false;
        this._processes = new Set();
        this._busy = false;
        this._switching = false;
        this.menuManager = new PopupMenu.PopupMenuManager(this);
        this.menu = new Applet.AppletPopupMenu(this, orientation);
        this.menuManager.addMenu(this.menu);
        this._identity = new PopupMenu.PopupMenuItem('', { reactive: false });
        this.menu.addMenuItem(this._identity);
        this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());
        this._change = new PopupMenu.PopupMenuItem('Сменить сотрудника');
        this._change.connect('activate', () => this._switch());
        this.menu.addMenuItem(this._change);
        this._error = new PopupMenu.PopupMenuItem('Не удалось открыть вход. Заблокируй экран и выбери свою учётку.', { reactive: false });
        this.menu.addMenuItem(this._error);
        this._error.actor.hide();
        this._showUnknown();
        this._refresh();
        this._timer = Mainloop.timeout_add_seconds(3, () => { this._refresh(); return true; });
    }

    _showUnknown() {
        this.set_applet_label('Сотрудник не определён — войти');
        this.set_applet_tooltip('Нажми, чтобы войти под своей учёткой');
        this._identity.label.set_text('Сотрудник не определён');
    }

    _run(command, timeout, done) {
        let process;
        try {
            process = Gio.Subprocess.new(['/usr/bin/python3', HELPER, command],
                Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_SILENCE);
        } catch (e) { done(false, ''); return; }
        this._processes.add(process);
        let timedOut = false;
        let timer = Mainloop.timeout_add_seconds(timeout, () => {
            timedOut = true;
            timer = 0;
            process.force_exit();
            return false;
        });
        process.communicate_utf8_async(null, null, (proc, result) => {
            if (timer) Mainloop.source_remove(timer);
            this._processes.delete(process);
            if (this._removed) return;
            try {
                let [ok, stdout] = proc.communicate_utf8_finish(result);
                done(ok && !timedOut && proc.get_successful(), stdout);
            } catch (e) { done(false, ''); }
        });
    }

    _refresh() {
        if (this._busy || this._removed) return;
        this._busy = true;
        this._run('status', 4, (ok, text) => {
            this._busy = false;
            try {
                if (!ok) throw new Error('unavailable');
                const data = JSON.parse(text);
                if (data.state !== 'ok' || typeof data.name !== 'string' ||
                    !/^[a-z0-9_.@-]{1,127}$/.test(data.login)) throw new Error('invalid');
                const name = data.name.length > 32 ? data.name.slice(0, 31) + '…' : data.name;
                this.set_applet_label(`Сейчас работает: ${name} · ${data.login}`);
                this.set_applet_tooltip(`${data.name} · ${data.login}\nНажми, чтобы сменить сотрудника`);
                this._identity.label.set_text(`${data.name} · ${data.login}`);
            } catch (e) { this._showUnknown(); }
        });
    }

    _switch() {
        if (this._switching) return;
        this._switching = true;
        this._error.actor.hide();
        this._change.setSensitive(false);
        this.menu.close();
        this._run('switch', 18, (ok) => {
            this._switching = false;
            this._change.setSensitive(true);
            if (!ok) {
                this._error.actor.show();
                this.menu.open();
            }
            this._refresh();
        });
    }

    on_applet_clicked() { this.menu.toggle(); }

    on_applet_removed_from_panel() {
        this._removed = true;
        if (this._timer) Mainloop.source_remove(this._timer);
        for (const process of this._processes) process.force_exit();
        this.menu.destroy();
    }
}

function main(metadata, orientation, panel_height, instance_id) {
    return new EmployeeApplet(orientation, panel_height, instance_id);
}
