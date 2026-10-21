#!/usr/bin/python3
"""Unprivileged GTK wizard; one authenticated backend over private stdin."""
import json
import os
from pathlib import Path
import subprocess
import threading
import sys
import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GLib

ENTRY = '/usr/local/lib/office-local-transition/entry.py'


class Wizard(Gtk.Window):
    def __init__(self, demo=False):
        super().__init__(title='Переход на локальную учётку')
        self.set_default_size(760, 720)
        self.set_border_width(24)
        self.connect('destroy', self.close)
        self.demo = demo
        self.backend = None
        self.job_id = None
        self.recovery = False
        self.rpc_lock = threading.Lock()
        self.inventory = None
        shell = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        self.add(shell)
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        shell.pack_start(scroller, True, True, 0)
        self.box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        scroller.add(self.box)
        title = Gtk.Label(xalign=0)
        title.set_markup('<span size="x-large" weight="bold">Локальный вход без домена</span>')
        self.box.pack_start(title, False, False, 0)
        self.info = Gtk.Label(label='Проверяем учётку, приложения и настройки входа…', xalign=0)
        self.info.set_line_wrap(True)
        self.box.pack_start(self.info, False, False, 0)
        self.fields = Gtk.Grid(column_spacing=18, row_spacing=12)
        self.box.pack_start(self.fields, False, False, 0)
        self.mode = Gtk.ComboBoxText()
        self.mode.append('new', 'Задать новый пароль')
        self.mode.append('local', 'Использовать пароль старой локальной учётки')
        self.mode.set_active_id('local')
        self.source = Gtk.ComboBoxText()
        self.password = Gtk.Entry(visibility=False, input_purpose=Gtk.InputPurpose.PASSWORD)
        self.confirm = Gtk.Entry(visibility=False, input_purpose=Gtk.InputPurpose.PASSWORD)
        self.admin = Gtk.Entry(text='office-admin')
        self.admin_password = Gtk.Entry(visibility=False, input_purpose=Gtk.InputPurpose.PASSWORD)
        self.admin_confirm = Gtk.Entry(visibility=False, input_purpose=Gtk.InputPurpose.PASSWORD)
        self.key = Gtk.Entry()
        self.key.set_placeholder_text('Публичный SSH-ключ, если нужен удалённый доступ')
        self.queue = Gtk.ComboBoxText()
        self.queue.append('archive', 'Временно сохранить очередь Пульса в закрытом резерве')
        self.queue.append('delete', 'Удалить локальную очередь Пульса')
        self.queue.set_active_id('archive')
        labels = [('Пароль', self.mode), ('Старая локальная учётка', self.source),
                  ('Пароль рабочего входа', self.password), ('Повтор пароля', self.confirm),
                  ('Локальный администратор', self.admin), ('Пароль администратора', self.admin_password),
                  ('Повтор пароля администратора', self.admin_confirm), ('SSH-ключ администратора', self.key),
                  ('Данные Пульса', self.queue)]
        for row, (label, field) in enumerate(labels):
            self.fields.attach(Gtk.Label(label=label, xalign=0), 0, row, 1, 1)
            field.set_hexpand(True)
            self.fields.attach(field, 1, row, 1, 1)
        self.ack = Gtk.CheckButton(label='Я сохранил работу и выключил VM. Рабочий сеанс можно завершить.')
        self.box.pack_start(self.ack, False, False, 0)
        self.status = Gtk.Label(xalign=0)
        self.status.set_line_wrap(True)
        self.status.set_selectable(True)
        self.box.pack_start(self.status, True, True, 0)
        buttons = Gtk.Box(spacing=12)
        self.preview = Gtk.Button(label='Проверить и показать план')
        self.apply = Gtk.Button(label='Начать переход')
        self.restore = Gtk.Button(label='Вернуть прежние настройки входа')
        self.restore.set_no_show_all(True)
        self.restore.connect('clicked', self.rollback)
        self.finish = Gtk.Button(label='Вход и приложения проверены')
        self.finish.set_no_show_all(True)
        self.finish.connect('clicked', self.accept)
        self.apply.set_sensitive(False)
        self.preview.connect('clicked', self.preview_plan)
        self.apply.connect('clicked', self.start)
        buttons.pack_end(self.apply, False, False, 0)
        buttons.pack_end(self.preview, False, False, 0)
        buttons.pack_start(self.restore, False, False, 0)
        buttons.pack_start(self.finish, False, False, 0)
        shell.pack_end(buttons, False, False, 0)
        for field in (self.mode, self.source, self.queue):
            field.connect('changed', lambda *_: self.invalidate())
        for field in (self.password, self.confirm, self.admin, self.admin_password, self.admin_confirm, self.key):
            field.connect('changed', lambda *_: self.invalidate())
        self.ack.connect('toggled', lambda *_: self.invalidate())
        self.show_all()
        if demo:
            self.loaded({'hostname': 'example.invalid', 'target': {'name': 'office-workspace',
                         'home': '/home/office-workspace', 'uid': 1001},
                         'password_sources': [{'name': 'example-user', 'available': True}], 'blockers': []})
        else:
            self.request({'action': 'inspect'}, self.loaded)

    def close(self, *_):
        if self.backend:
            self.backend.stdin.close()
        Gtk.main_quit()

    def invalidate(self):
        self.apply.set_sensitive(self.recovery)

    def request(self, payload, callback):
        def work():
            try:
                with self.rpc_lock:
                    if not self.backend:
                        self.backend = subprocess.Popen(['pkexec', '/usr/local/lib/office-local-transition/backend', 'rpc'],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
                    self.backend.stdin.write(json.dumps(payload)+'\n')
                    self.backend.stdin.flush()
                    response = json.loads(self.backend.stdout.readline())
                if not response.get('ok'):
                    raise RuntimeError(response.get('error', 'Не выполнено'))
                GLib.idle_add(callback, response['result'])
            except Exception as error:
                GLib.idle_add(self.status.set_text, str(error))
            finally:
                GLib.idle_add(self.preview.set_sensitive, True)
        self.preview.set_sensitive(False)
        threading.Thread(target=work, daemon=True).start()

    def loaded(self, inventory):
        self.inventory = inventory
        target = inventory.get('target')
        if target:
            self.info.set_text(f"{inventory['hostname']} · {target['name']}\n"
                f"Рабочая папка: {target['home']}. Учётка и данные остаются на месте.\n"
                'Будет включён обычный экран входа Mint и удалён Пульс.\n'
                'Для сохранения паролей приложений введи выбранный пароль рабочего входа.')
        for source in inventory.get('password_sources', []):
            if source['available']:
                self.source.append(source['name'], source['name'])
        self.source.set_active(0)
        if inventory.get('blockers'):
            self.status.set_text('\n'.join(inventory['blockers']))
            self.preview.set_sensitive(False)
        if not self.demo:
            directory = Path('/var/lib/office-local-transition/public')
            files = sorted(directory.glob('*.json'), key=lambda p: p.stat().st_mtime, reverse=True)
            if files:
                try:
                    state = json.loads(files[0].read_text())
                    if state['status'] != 'rolled_back':
                        self.request({'action': 'job', 'id': state['id']}, self.loaded_job)
                except (OSError, ValueError, KeyError):
                    pass

    def loaded_job(self, result):
        state, opts = result['state'], result['options']
        self.job_id = state['id']
        self.mode.set_active_id(opts['password_mode'])
        self.source.set_active_id(opts['source_user'])
        self.admin.set_text(opts['admin_user'])
        self.key.set_text(opts['admin_public_key'].strip())
        self.queue.set_active_id(opts['queue_policy'])
        self.status.set_text(state.get('current_step', state['status'])+'\n'+state.get('error', '')+
                             '\n'+'\n'.join(state.get('warnings', [])))
        if state['status'] in ('blocked', 'interrupted', 'prepared'):
            self.recovery = True
            self.apply.set_label('Продолжить прежнее задание')
            self.apply.set_sensitive(True)
            for field in (self.mode, self.source, self.admin, self.key, self.queue):
                field.set_sensitive(False)
            if not state.get('unenrollment_started'):
                self.restore.show()
        elif state['status'] == 'awaiting_user_check':
            self.fields.set_sensitive(False)
            self.apply.set_sensitive(False)
            self.status.set_text('Локальный вход подготовлен. Войди выбранным паролем и проверь приложения.\n'
                                 'Загрузка и серверная очистка проверяются отдельно.\n'+
                                 '\n'.join(state.get('warnings', [])))
            self.apply.hide()
            self.preview.hide()
            self.finish.show()
        elif state['status'] in ('awaiting_reboot', 'server_cleanup_pending', 'complete'):
            self.fields.set_sensitive(False)
            self.apply.hide()
            self.preview.hide()
            self.finish.hide()
            labels = {'local_auth': 'Вход с локальным паролем', 'profile_identity': 'Рабочая учётка и данные',
                      'display_manager': 'Экран входа', 'pulse_removed': 'Удаление Пульса',
                      'graphical_login': 'Вход на рабочий стол', 'applications': 'Приложения',
                      'reboot': 'Загрузка компьютера', 'server_cleanup': 'Регистрация на сервере FreeIPA'}
            checked = state.get('verified', {})
            self.status.set_text('\n'.join(label+': '+('проверено' if checked.get(key) else 'ожидает проверки')
                                            for key, label in labels.items()))
        else:
            self.fields.set_sensitive(False)
            GLib.timeout_add_seconds(1, self.poll)

    def rollback(self, *_):
        if not self.ack.get_active():
            self.status.set_text('Перед восстановлением сохрани работу и подтверди завершение сеанса.')
            return
        dialog = Gtk.MessageDialog(transient_for=self, modal=True, message_type=Gtk.MessageType.WARNING,
            buttons=Gtk.ButtonsType.OK_CANCEL, text='Вернуть прежние настройки входа и связку ключей?')
        dialog.format_secondary_text('Рабочие данные остаются на месте. Локальный администратор сохранится.')
        response = dialog.run()
        dialog.destroy()
        if response == Gtk.ResponseType.OK:
            self.request({'action': 'rollback', 'id': self.job_id},
                         lambda state: self.status.set_text(state['current_step']))

    def accept(self, *_):
        self.request({'action': 'accept', 'id': self.job_id, 'applications': True},
                     lambda state: self.loaded_job({'state': state, 'options': self.options()}))

    def options(self):
        return {'password_mode': self.mode.get_active_id(), 'source_user': self.source.get_active_id() or '',
                'admin_user': self.admin.get_text().strip(), 'admin_public_key': self.key.get_text().strip(),
                'close_session': self.ack.get_active(), 'queue_policy': self.queue.get_active_id()}

    def preview_plan(self, *_):
        if self.demo:
            self.status.set_text('Просмотр интерфейса. Системные изменения отключены.')
            return
        self.request({'action': 'plan', 'options': self.options()}, self.show_plan)

    def show_plan(self, planned):
        self.status.set_text('\n'.join('• '+action for action in planned['actions'])+
                             '\n\nРабочие файлы не переносятся. Перезагрузка отдельно.')
        self.apply.set_sensitive(True)

    def start(self, *_):
        if self.demo:
            return
        if not self.ack.get_active():
            self.status.set_text('Сохрани работу и подтверди завершение сеанса.')
            return
        if self.password.get_text() != self.confirm.get_text():
            self.status.set_text('Пароли рабочего входа не совпадают.')
            return
        if self.admin_password.get_text() != self.admin_confirm.get_text():
            self.status.set_text('Пароли администратора не совпадают.')
            return
        self.apply.set_sensitive(False)
        payload = {'action': 'resume' if self.recovery else 'dispatch', 'options': self.options(), 'secrets': {
            'password': self.password.get_text(), 'admin_password': self.admin_password.get_text()}}
        if self.recovery:
            payload['id'] = self.job_id
        self.request(payload, self.dispatched)

    def dispatched(self, result):
        self.job_id = result['id']
        for field in (self.password, self.confirm, self.admin_password, self.admin_confirm):
            field.set_text('')
        self.fields.set_sensitive(False)
        self.ack.set_sensitive(False)
        self.preview.set_sensitive(False)
        self.status.set_text('Задание выполняется. После переключения входа войди локальным паролем.')
        GLib.timeout_add_seconds(1, self.poll)

    def poll(self):
        try:
            state = json.loads(Path('/var/lib/office-local-transition/public/'+self.job_id+'.json').read_text())
            text = state.get('current_step', state['status'])+'\n'+state.get('error', '')
            if 'Проверка нового SSH-входа' in state.get('current_step', ''):
                text += '\nВ новом SSH-сеансе локального администратора выполни:\n'
                text += 'sudo office-local-transition confirm-admin '+self.job_id
            self.status.set_text(text)
            return state['status'] not in ('blocked', 'awaiting_user_check', 'rolled_back')
        except (OSError, ValueError):
            return True


if __name__ == '__main__':
    window = Wizard(demo='--demo' in sys.argv)
    if '--screenshot' in sys.argv:
        if '--demo' not in sys.argv:
            raise SystemExit('Screenshots are supported only in demo mode')
        destination = sys.argv[sys.argv.index('--screenshot')+1]
        def capture():
            from gi.repository import Gdk
            drawing = window.get_window()
            width, height = drawing.get_width(), drawing.get_height()
            pixbuf = Gdk.pixbuf_get_from_window(drawing, 0, 0, width, height)
            pixbuf.savev(destination, 'png', [], [])
            window.destroy()
            return False
        GLib.timeout_add(800, capture)
    Gtk.main()
