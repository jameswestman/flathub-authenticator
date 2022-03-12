flathub_authenticator_sources = [
  'main.c',
]

flathub_authenticator_deps = [
  dependency('gio-2.0'),
  dependency('gio-unix-2.0'),
  dependency('libsoup-2.4'),
]

gnome = import('gnome')

flatpak_authenticator_dbus_src = gnome.gdbus_codegen('org.freedesktop.Flatpak.Authenticator',
  sources: ['org.freedesktop.Flatpak.Authenticator.xml'],
  interface_prefix: 'org.freedesktop',
)

application_dbus_src = gnome.gdbus_codegen('org.freedesktop.Application',
  sources: ['org.freedesktop.Application.xml'],
  interface_prefix: 'org.freedesktop',
)

executable('flathub-authenticator',
  flathub_authenticator_sources,
  flatpak_authenticator_dbus_src,
  application_dbus_src,
  dependencies: flathub_authenticator_deps,
  install: true,
)
