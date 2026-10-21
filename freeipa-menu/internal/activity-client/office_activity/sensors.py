"""X11 count-only sensor and local session state. Never translate keycodes."""
import ctypes
import threading


class SessionBus:
    def __init__(self, session):
        from gi.repository import Gio, GLib
        self.Gio, self.GLib = Gio, GLib
        self.system = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
        self.user = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        self.path = self.system.call_sync('org.freedesktop.login1', '/org/freedesktop/login1',
            'org.freedesktop.login1.Manager', 'GetSession', GLib.Variant('(s)', (session,)),
            GLib.VariantType.new('(o)'), Gio.DBusCallFlags.NONE, 1500, None).unpack()[0]

    def properties(self):
        return self.system.call_sync('org.freedesktop.login1', self.path,
            'org.freedesktop.DBus.Properties', 'GetAll',
            self.GLib.Variant('(s)', ('org.freedesktop.login1.Session',)),
            self.GLib.VariantType.new('(a{sv})'), self.Gio.DBusCallFlags.NONE, 1500, None).unpack()[0]

    def locked(self):
        try:
            return self.user.call_sync('org.cinnamon.ScreenSaver', '/org/cinnamon/ScreenSaver',
                'org.cinnamon.ScreenSaver', 'GetActive', None,
                self.GLib.VariantType.new('(b)'), self.Gio.DBusCallFlags.NONE, 500, None).unpack()[0]
        except Exception:
            # Fail closed: do not count password prompts when lock sensor is absent.
            return None


class Idle:
    class Info(ctypes.Structure):
        _fields_ = [('window', ctypes.c_ulong), ('state', ctypes.c_int), ('kind', ctypes.c_int),
                    ('since', ctypes.c_ulong), ('idle', ctypes.c_ulong), ('mask', ctypes.c_ulong)]

    def __init__(self):
        self.x = ctypes.CDLL('libX11.so.6')
        self.s = ctypes.CDLL('libXss.so.1')
        self.x.XOpenDisplay.argtypes = [ctypes.c_char_p]
        self.x.XOpenDisplay.restype = ctypes.c_void_p
        self.x.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
        self.x.XDefaultRootWindow.restype = ctypes.c_ulong
        self.x.XCloseDisplay.argtypes = [ctypes.c_void_p]
        self.s.XScreenSaverQueryInfo.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(self.Info)]
        self.display = self.x.XOpenDisplay(None)
        if not self.display:
            raise RuntimeError('X_display_unavailable')
        self.root = self.x.XDefaultRootWindow(self.display)

    def seconds(self):
        info = self.Info()
        if not self.s.XScreenSaverQueryInfo(self.display, self.root, ctypes.byref(info)):
            return None
        return info.idle / 1000.0

    def close(self):
        self.x.XCloseDisplay(self.display)


class Keyboard:
    def __init__(self, callback):
        self.callback = callback
        self.ready = threading.Event()
        self.failed = False
        self.control = self.context = None
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        from Xlib import X, display
        from Xlib.ext import record
        data_display = None
        try:
            self.control = display.Display()
            data_display = display.Display()
            if not data_display.has_extension('RECORD'):
                raise RuntimeError('X_RECORD_unavailable')
            self.context = self.control.record_create_context(0, [record.AllClients], [{
                'core_requests': (0, 0), 'core_replies': (0, 0),
                'ext_requests': (0, 0, 0, 0), 'ext_replies': (0, 0, 0, 0),
                'delivered_events': (0, 0), 'device_events': (X.KeyPress, X.KeyPress),
                'errors': (0, 0), 'client_started': False, 'client_died': False}])
            self.control.sync()

            def receive(reply):
                if reply.category == record.StartOfData:
                    self.ready.set()
                elif reply.category == record.FromServer:
                    # Core events are 32 bytes. Read ONLY their event type byte.
                    # Keycode, text, coordinates and other payload are never decoded.
                    for offset in range(0, len(reply.data), 32):
                        if reply.data[offset] & 0x7f == X.KeyPress:
                            self.callback()

            data_display.record_enable_context(self.context, receive)
        except Exception:
            self.failed = True
            self.ready.set()
        finally:
            if data_display:
                data_display.close()

    def start(self):
        self.thread.start()
        if not self.ready.wait(5) or self.failed:
            raise RuntimeError('keyboard_sensor_unavailable')

    def close(self):
        if self.control and self.context:
            self.control.record_disable_context(self.context)
            self.control.sync()
            self.thread.join(2)
            self.control.record_free_context(self.context)
            self.control.close()
