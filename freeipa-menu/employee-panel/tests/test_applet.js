// Exercise UI state transitions without installing anything into Cinnamon.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
let jobs = [], timers = new Map(), nextTimer = 1;
class Item {
    constructor(text) {
        this.text = text;
        this.label = {set_text: value => { this.text = value; }};
        this.actor = {hide: () => {this.hidden = true;}, show: () => {this.hidden = false;}};
    }
    connect(event, callback) { this.activate = callback; }
    setSensitive(value) { this.sensitive = value; }
}
class Menu {
    addMenuItem() {}
    toggle() { this.opened = !this.opened; }
    open() { this.opened = true; }
    close() { this.opened = false; }
    destroy() { this.destroyed = true; }
}
class Process {
    constructor(argv) { this.command = argv.at(-1); this.success = true; this.killed = false; }
    communicate_utf8_async(input, cancel, callback) { this.callback = callback; jobs.push(this); }
    communicate_utf8_finish() { return [true, this.output || '']; }
    get_successful() { return this.success; }
    force_exit() { this.killed = true; }
    finish(value, success = true) {
        this.output = typeof value === 'string' ? value : JSON.stringify(value);
        this.success = success;
        this.callback(this, {});
    }
}
const context = vm.createContext({imports: {
    ui: {applet: {
        TextApplet: class {
            setAllowedLayout() {}
            set_applet_label(value) {this.label = value;}
            set_applet_tooltip(value) {this.tooltip = value;}
        }, AllowedLayout: {BOTH: 3}, AppletPopupMenu: Menu
    }, popupMenu: {PopupMenuManager: class {addMenu() {}}, PopupMenuItem: Item, PopupSeparatorMenuItem: Item}},
    gi: {Gio: {Subprocess: {new: argv => new Process(argv)}, SubprocessFlags: {STDOUT_PIPE: 1, STDERR_SILENCE: 2}}},
    mainloop: {timeout_add_seconds: (seconds, callback) => {let id = nextTimer++; timers.set(id, {seconds, callback}); return id;}, source_remove: id => timers.delete(id)}
}});
vm.runInContext(fs.readFileSync(require('node:path').join(__dirname, '../applet/applet.js'), 'utf8'), context);
const app = vm.runInContext('main({}, 0, 32, 1)', context);
assert.match(app.label, /не определён/);
assert.equal(jobs.length, 1);
app._refresh();
assert.equal(jobs.length, 1, 'overlapping NSS requests prevented');
jobs.shift().finish({state: 'ok', name: 'Артём', login: 'avi1'});
assert.equal(app.label, 'Сейчас работает: Артём · avi1');
app._refresh(); jobs.shift().finish({state: 'unknown'}, false);
assert.match(app.label, /не определён/, 'old identity cleared on failure');
app._refresh();
const hung = jobs.shift();
[...timers.values()].find(t => t.seconds === 4).callback();
assert.ok(hung.killed);
hung.finish({state: 'ok', name: 'Old', login: 'avi1'});
assert.match(app.label, /не определён/, 'timed out response cannot restore old label');
app._switch();
const switching = jobs.shift();
assert.equal(switching.command, 'switch');
app._switch(); assert.equal(jobs.length, 0, 'double clicks suppressed');
switching.finish('', false);
assert.equal(app._error.hidden, false);
jobs.shift().finish({state: 'ok', name: 'Новый', login: 'avi2'});
assert.equal(app._error.hidden, false, 'refresh does not erase switch error');
assert.equal(app.label, 'Сейчас работает: Новый · avi2');
app._refresh();
const pending = jobs.shift();
app.on_applet_removed_from_panel();
assert.ok(pending.killed);
pending.finish({state: 'ok', name: 'Не применять', login: 'avi3'});
assert.equal(app.label, 'Сейчас работает: Новый · avi2');
assert.ok(app.menu.destroyed);
console.log('Applet state tests passed: identity changes, unknown, timeout, switching, cleanup');
