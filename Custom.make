#

_CUSTOM_SUBDIRS_ = \
	gpbs

_CUSTOM_EXTRA_DIST_ = \
	Custom.m4 \
	Custom.make

_CUSTOM_plugin_ldadd_ = \
	-dlopen plugins/gpbs/gpbs.la
