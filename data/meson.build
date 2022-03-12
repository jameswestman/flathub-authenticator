desktop_file = i18n.merge_file(
  input: 'org.flathub.Authenticator.desktop.in',
  output: 'org.flathub.Authenticator.desktop',
  type: 'desktop',
  po_dir: '../po',
  install: true,
  install_dir: join_paths(get_option('datadir'), 'applications')
)

desktop_utils = find_program('desktop-file-validate', required: false)
if desktop_utils.found()
  test('Validate desktop file', desktop_utils,
    args: [desktop_file]
  )
endif

configure_file(
  input: 'org.flathub.Authenticator.service.in',
  output: 'org.flathub.Authenticator.service',
  configuration: {
    'bindir': join_paths(get_option('prefix'), get_option('bindir')),
  },
  install: true,
  install_dir: join_paths(get_option('datadir'), 'dbus-1', 'services'),
)
