from setuptools import setup
import setup_translate

pkg = 'SystemPlugins.NetworkBrowser'
setup(name='enigma2-plugin-systemplugins-networkbrowser',
       version='3.0',
       description='Networkbrowser and Network-Mountmanager',
       package_dir={pkg: 'NetworkBrowser'},
       packages=[pkg],
       package_data={pkg: ['images/*.png', '*.png', '*.xml', 'locale/*/LC_MESSAGES/*.mo', '*.info', 'LICENSE', 'icons/*.png', 'icons/LICENSE']},
       cmdclass=setup_translate.cmdclass,  # for translation
      )
