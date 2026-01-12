# generated automatically by aclocal 1.16.5 -*- Autoconf -*-

# Copyright (C) 1996-2021 Free Software Foundation, Inc.

# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.

m4_ifndef([AC_CONFIG_MACRO_DIRS], [m4_defun([_AM_CONFIG_MACRO_DIRS], [])m4_defun([AC_CONFIG_MACRO_DIRS], [_AM_CONFIG_MACRO_DIRS($@)])])
m4_ifndef([AC_AUTOCONF_VERSION],
  [m4_copy([m4_PACKAGE_VERSION], [AC_AUTOCONF_VERSION])])dnl
m4_if(m4_defn([AC_AUTOCONF_VERSION]), [2.71],,
[m4_warning([this file was generated for autoconf 2.71.
You have another version of autoconf.  It may work, but is not guaranteed to.
If you have problems, you may need to regenerate the build system entirely.
To do so, use the procedure documented by the package, typically 'autoreconf'.])])

# Copyright (C) 2002-2021 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# AM_AUTOMAKE_VERSION(VERSION)
# ----------------------------
# Automake X.Y traces this macro to ensure aclocal.m4 has been
# generated from the m4 files accompanying Automake X.Y.
# (This private macro should not be called outside this file.)
AC_DEFUN([AM_AUTOMAKE_VERSION],
[am__api_version='1.16'
dnl Some users find AM_AUTOMAKE_VERSION and mistake it for a way to
dnl require some minimum version.  Point them to the right macro.
m4_if([$1], [1.16.5], [],
      [AC_FATAL([Do not call $0, use AM_INIT_AUTOMAKE([$1]).])])dnl
])

# _AM_AUTOCONF_VERSION(VERSION)
# -----------------------------
# aclocal traces this macro to find the Autoconf version.
# This is a private macro too.  Using m4_define simplifies
# the logic in aclocal, which can simply ignore this definition.
m4_define([_AM_AUTOCONF_VERSION], [])

# AM_SET_CURRENT_AUTOMAKE_VERSION
# -------------------------------
# Call AM_AUTOMAKE_VERSION and AM_AUTOMAKE_VERSION so they can be traced.
# This function is AC_REQUIREd by AM_INIT_AUTOMAKE.
AC_DEFUN([AM_SET_CURRENT_AUTOMAKE_VERSION],
[AM_AUTOMAKE_VERSION([1.16.5])dnl
m4_ifndef([AC_AUTOCONF_VERSION],
  [m4_copy([m4_PACKAGE_VERSION], [AC_AUTOCONF_VERSION])])dnl
_AM_AUTOCONF_VERSION(m4_defn([AC_AUTOCONF_VERSION]))])

# AM_AUX_DIR_EXPAND                                         -*- Autoconf -*-

# Copyright (C) 2001-2021 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# For projects using AC_CONFIG_AUX_DIR([foo]), Autoconf sets
# $ac_aux_dir to '$srcdir/foo'.  In other projects, it is set to
# '$srcdir', '$srcdir/..', or '$srcdir/../..'.
#
# Of course, Automake must honor this variable whenever it calls a
# tool from the auxiliary directory.  The problem is that $srcdir (and
# therefore $ac_aux_dir as well) can be either absolute or relative,
# depending on how configure is run.  This is pretty annoying, since
# it makes $ac_aux_dir quite unusable in subdirectories: in the top
# source directory, any form will work fine, but in subdirectories a
# relative path needs to be adjusted first.
#
# $ac_aux_dir/missing
#    fails when called from a subdirectory if $ac_aux_dir is relative
# $top_srcdir/$ac_aux_dir/missing
#    fails if $ac_aux_dir is absolute,
#    fails when called from a subdirectory in a VPATH build with
#          a relative $ac_aux_dir
#
# The reason of the latter failure is that $top_srcdir and $ac_aux_dir
# are both prefixed by $srcdir.  In an in-source build this is usually
# harmless because $srcdir is '.', but things will broke when you
# start a VPATH build or use an absolute $srcdir.
#
# So we could use something similar to $top_srcdir/$ac_aux_dir/missing,
# iff we strip the leading $srcdir from $ac_aux_dir.  That would be:
#   am_aux_dir='\$(top_srcdir)/'`expr "$ac_aux_dir" : "$srcdir//*\(.*\)"`
# and then we would define $MISSING as
#   MISSING="\${SHELL} $am_aux_dir/missing"
# This will work as long as MISSING is not called from configure, because
# unfortunately $(top_srcdir) has no meaning in configure.
# However there are other variables, like CC, which are often used in
# configure, and could therefore not use this "fixed" $ac_aux_dir.
#
# Another solution, used here, is to always expand $ac_aux_dir to an
# absolute PATH.  The drawback is that using absolute paths prevent a
# configured tree to be moved without reconfiguration.

AC_DEFUN([AM_AUX_DIR_EXPAND],
[AC_REQUIRE([AC_CONFIG_AUX_DIR_DEFAULT])dnl
# Expand $ac_aux_dir to an absolute path.
am_aux_dir=`cd "$ac_aux_dir" && pwd`
])

# Do all the work for Automake.                             -*- Autoconf -*-

# Copyright (C) 1996-2021 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This macro actually does too much.  Some checks are only needed if
# your package does certain things.  But this isn't really a big deal.

dnl Redefine AC_PROG_CC to automatically invoke _AM_PROG_CC_C_O.
m4_define([AC_PROG_CC],
m4_defn([AC_PROG_CC])
[_AM_PROG_CC_C_O
])

# AM_INIT_AUTOMAKE(PACKAGE, VERSION, [NO-DEFINE])
# AM_INIT_AUTOMAKE([OPTIONS])
# -----------------------------------------------
# The call with PACKAGE and VERSION arguments is the old style
# call (pre autoconf-2.50), which is being phased out.  PACKAGE
# and VERSION should now be passed to AC_INIT and removed from
# the call to AM_INIT_AUTOMAKE.
# We support both call styles for the transition.  After
# the next Automake release, Autoconf can make the AC_INIT
# arguments mandatory, and then we can depend on a new Autoconf
# release and drop the old call support.
AC_DEFUN([AM_INIT_AUTOMAKE],
[AC_PREREQ([2.65])dnl
m4_ifdef([_$0_ALREADY_INIT],
  [m4_fatal([$0 expanded multiple times
]m4_defn([_$0_ALREADY_INIT]))],
  [m4_define([_$0_ALREADY_INIT], m4_expansion_stack)])dnl
dnl Autoconf wants to disallow AM_ names.  We explicitly allow
dnl the ones we care about.
m4_pattern_allow([^AM_[A-Z]+FLAGS$])dnl
AC_REQUIRE([AM_SET_CURRENT_AUTOMAKE_VERSION])dnl
AC_REQUIRE([AC_PROG_INSTALL])dnl
if test "`cd $srcdir && pwd`" != "`pwd`"; then
  # Use -I$(srcdir) only when $(srcdir) != ., so that make's output
  # is not polluted with repeated "-I."
  AC_SUBST([am__isrc], [' -I$(srcdir)'])_AM_SUBST_NOTMAKE([am__isrc])dnl
  # test to see if srcdir already configured
  if test -f $srcdir/config.status; then
    AC_MSG_ERROR([source directory already configured; run "make distclean" there first])
  fi
fi

# test whether we have cygpath
if test -z "$CYGPATH_W"; then
  if (cygpath --version) >/dev/null 2>/dev/null; then
    CYGPATH_W='cygpath -w'
  else
    CYGPATH_W=echo
  fi
fi
AC_SUBST([CYGPATH_W])

# Define the identity of the package.
dnl Distinguish between old-style and new-style calls.
m4_ifval([$2],
[AC_DIAGNOSE([obsolete],
             [$0: two- and three-arguments forms are deprecated.])
m4_ifval([$3], [_AM_SET_OPTION([no-define])])dnl
 AC_SUBST([PACKAGE], [$1])dnl
 AC_SUBST([VERSION], [$2])],
[_AM_SET_OPTIONS([$1])dnl
dnl Diagnose old-style AC_INIT with new-style AM_AUTOMAKE_INIT.
m4_if(
  m4_ifset([AC_PACKAGE_NAME], [ok]):m4_ifset([AC_PACKAGE_VERSION], [ok]),
  [ok:ok],,
  [m4_fatal([AC_INIT should be called with package and version arguments])])dnl
 AC_SUBST([PACKAGE], ['AC_PACKAGE_TARNAME'])dnl
 AC_SUBST([VERSION], ['AC_PACKAGE_VERSION'])])dnl

_AM_IF_OPTION([no-define],,
[AC_DEFINE_UNQUOTED([PACKAGE], ["$PACKAGE"], [Name of package])
 AC_DEFINE_UNQUOTED([VERSION], ["$VERSION"], [Version number of package])])dnl

# Some tools Automake needs.
AC_REQUIRE([AM_SANITY_CHECK])dnl
AC_REQUIRE([AC_ARG_PROGRAM])dnl
AM_MISSING_PROG([ACLOCAL], [aclocal-${am__api_version}])
AM_MISSING_PROG([AUTOCONF], [autoconf])
AM_MISSING_PROG([AUTOMAKE], [automake-${am__api_version}])
AM_MISSING_PROG([AUTOHEADER], [autoheader])
AM_MISSING_PROG([MAKEINFO], [makeinfo])
AC_REQUIRE([AM_PROG_INSTALL_SH])dnl
AC_REQUIRE([AM_PROG_INSTALL_STRIP])dnl
AC_REQUIRE([AC_PROG_MKDIR_P])dnl
# For better backward compatibility.  To be removed once Automake 1.9.x
# dies out for good.  For more background, see:
# <https://lists.gnu.org/archive/html/automake/2012-07/msg00001.html>
# <https://lists.gnu.org/archive/html/automake/2012-07/msg00014.html>
AC_SUBST([mkdir_p], ['$(MKDIR_P)'])
# We need awk for the "check" target (and possibly the TAP driver).  The
# system "awk" is bad on some platforms.
AC_REQUIRE([AC_PROG_AWK])dnl
AC_REQUIRE([AC_PROG_MAKE_SET])dnl
AC_REQUIRE([AM_SET_LEADING_DOT])dnl
_AM_IF_OPTION([tar-ustar], [_AM_PROG_TAR([ustar])],
	      [_AM_IF_OPTION([tar-pax], [_AM_PROG_TAR([pax])],
			     [_AM_PROG_TAR([v7])])])
_AM_IF_OPTION([no-dependencies],,
[AC_PROVIDE_IFELSE([AC_PROG_CC],
		  [_AM_DEPENDENCIES([CC])],
		  [m4_define([AC_PROG_CC],
			     m4_defn([AC_PROG_CC])[_AM_DEPENDENCIES([CC])])])dnl
AC_PROVIDE_IFELSE([AC_PROG_CXX],
		  [_AM_DEPENDENCIES([CXX])],
		  [m4_define([AC_PROG_CXX],
			     m4_defn([AC_PROG_CXX])[_AM_DEPENDENCIES([CXX])])])dnl
AC_PROVIDE_IFELSE([AC_PROG_OBJC],
		  [_AM_DEPENDENCIES([OBJC])],
		  [m4_define([AC_PROG_OBJC],
			     m4_defn([AC_PROG_OBJC])[_AM_DEPENDENCIES([OBJC])])])dnl
AC_PROVIDE_IFELSE([AC_PROG_OBJCXX],
		  [_AM_DEPENDENCIES([OBJCXX])],
		  [m4_define([AC_PROG_OBJCXX],
			     m4_defn([AC_PROG_OBJCXX])[_AM_DEPENDENCIES([OBJCXX])])])dnl
])
# Variables for tags utilities; see am/tags.am
if test -z "$CTAGS"; then
  CTAGS=ctags
fi
AC_SUBST([CTAGS])
if test -z "$ETAGS"; then
  ETAGS=etags
fi
AC_SUBST([ETAGS])
if test -z "$CSCOPE"; then
  CSCOPE=cscope
fi
AC_SUBST([CSCOPE])

AC_REQUIRE([AM_SILENT_RULES])dnl
dnl The testsuite driver may need to know about EXEEXT, so add the
dnl 'am__EXEEXT' conditional if _AM_COMPILER_EXEEXT was seen.  This
dnl macro is hooked onto _AC_COMPILER_EXEEXT early, see below.
AC_CONFIG_COMMANDS_PRE(dnl
[m4_provide_if([_AM_COMPILER_EXEEXT],
  [AM_CONDITIONAL([am__EXEEXT], [test -n "$EXEEXT"])])])dnl

# POSIX will say in a future version that running "rm -f" with no argument
# is OK; and we want to be able to make that assumption in our Makefile
# recipes.  So use an aggressive probe to check that the usage we want is
# actually supported "in the wild" to an acceptable degree.
# See automake bug#10828.
# To make any issue more visible, cause the running configure to be aborted
# by default if the 'rm' program in use doesn't match our expectations; the
# user can still override this though.
if rm -f && rm -fr && rm -rf; then : OK; else
  cat >&2 <<'END'
Oops!

Your 'rm' program seems unable to run without file operands specified
on the command line, even when the '-f' option is present.  This is contrary
to the behaviour of most rm programs out there, and not conforming with
the upcoming POSIX standard: <http://austingroupbugs.net/view.php?id=542>

Please tell bug-automake@gnu.org about your system, including the value
of your $PATH and any error possibly output before this message.  This
can help us improve future automake versions.

END
  if test x"$ACCEPT_INFERIOR_RM_PROGRAM" = x"yes"; then
    echo 'Configuration will proceed anyway, since you have set the' >&2
    echo 'ACCEPT_INFERIOR_RM_PROGRAM variable to "yes"' >&2
    echo >&2
  else
    cat >&2 <<'END'
Aborting the configuration process, to ensure you take notice of the issue.

You can download and install GNU coreutils to get an 'rm' implementation
that behaves properly: <https://www.gnu.org/software/coreutils/>.

If you want to complete the configuration process using your problematic
'rm' anyway, export the environment variable ACCEPT_INFERIOR_RM_PROGRAM
to "yes", and re-run configure.

END
    AC_MSG_ERROR([Your 'rm' program is bad, sorry.])
  fi
fi
dnl The trailing newline in this macro's definition is deliberate, for
dnl backward compatibility and to allow trailing 'dnl'-style comments
dnl after the AM_INIT_AUTOMAKE invocation. See automake bug#16841.
])

dnl Hook into '_AC_COMPILER_EXEEXT' early to learn its expansion.  Do not
dnl add the conditional right here, as _AC_COMPILER_EXEEXT may be further
dnl mangled by Autoconf and run in a shell conditional statement.
m4_define([_AC_COMPILER_EXEEXT],
m4_defn([_AC_COMPILER_EXEEXT])[m4_provide([_AM_COMPILER_EXEEXT])])

# When config.status generates a header, we must update the stamp-h file.
# This file resides in the same directory as the config header
# that is generated.  The stamp files are numbered to have different names.

# Autoconf calls _AC_AM_CONFIG_HEADER_HOOK (when defined) in the
# loop where config.status creates the headers, so we can generate
# our stamp files there.
AC_DEFUN([_AC_AM_CONFIG_HEADER_HOOK],
[# Compute $1's index in $config_headers.
_am_arg=$1
_am_stamp_count=1
for _am_header in $config_headers :; do
  case $_am_header in
    $_am_arg | $_am_arg:* )
      break ;;
    * )
      _am_stamp_count=`expr $_am_stamp_count + 1` ;;
  esac
done
echo "timestamp for $_am_arg" >`AS_DIRNAME(["$_am_arg"])`/stamp-h[]$_am_stamp_count])

# Copyright (C) 2001-2021 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# AM_PROG_INSTALL_SH
# ------------------
# Define $install_sh.
AC_DEFUN([AM_PROG_INSTALL_SH],
[AC_REQUIRE([AM_AUX_DIR_EXPAND])dnl
if test x"${install_sh+set}" != xset; then
  case $am_aux_dir in
  *\ * | *\	*)
    install_sh="\${SHELL} '$am_aux_dir/install-sh'" ;;
  *)
    install_sh="\${SHELL} $am_aux_dir/install-sh"
  esac
fi
AC_SUBST([install_sh])])

# Copyright (C) 2003-2021 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# Check whether the underlying file-system supports filenames
# with a leading dot.  For instance MS-DOS doesn't.
AC_DEFUN([AM_SET_LEADING_DOT],
[rm -rf .tst 2>/dev/null
mkdir .tst 2>/dev/null
if test -d .tst; then
  am__leading_dot=.
else
  am__leading_dot=_
fi
rmdir .tst 2>/dev/null
AC_SUBST([am__leading_dot])])

# Fake the existence of programs that GNU maintainers use.  -*- Autoconf -*-

# Copyright (C) 1997-2021 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# AM_MISSING_PROG(NAME, PROGRAM)
# ------------------------------
AC_DEFUN([AM_MISSING_PROG],
[AC_REQUIRE([AM_MISSING_HAS_RUN])
$1=${$1-"${am_missing_run}$2"}
AC_SUBST($1)])

# AM_MISSING_HAS_RUN
# ------------------
# Define MISSING if not defined so far and test if it is modern enough.
# If it is, set am_missing_run to use it, otherwise, to nothing.
AC_DEFUN([AM_MISSING_HAS_RUN],
[AC_REQUIRE([AM_AUX_DIR_EXPAND])dnl
AC_REQUIRE_AUX_FILE([missing])dnl
if test x"${MISSING+set}" != xset; then
  MISSING="\${SHELL} '$am_aux_dir/missing'"
fi
# Use eval to expand $SHELL
if eval "$MISSING --is-lightweight"; then
  am_missing_run="$MISSING "
else
  am_missing_run=
  AC_MSG_WARN(['missing' script is too old or missing])
fi
])

# Helper functions for option handling.                     -*- Autoconf -*-

# Copyright (C) 2001-2021 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# _AM_MANGLE_OPTION(NAME)
# -----------------------
AC_DEFUN([_AM_MANGLE_OPTION],
[[_AM_OPTION_]m4_bpatsubst($1, [[^a-zA-Z0-9_]], [_])])

# _AM_SET_OPTION(NAME)
# --------------------
# Set option NAME.  Presently that only means defining a flag for this option.
AC_DEFUN([_AM_SET_OPTION],
[m4_define(_AM_MANGLE_OPTION([$1]), [1])])

# _AM_SET_OPTIONS(OPTIONS)
# ------------------------
# OPTIONS is a space-separated list of Automake options.
AC_DEFUN([_AM_SET_OPTIONS],
[m4_foreach_w([_AM_Option], [$1], [_AM_SET_OPTION(_AM_Option)])])

# _AM_IF_OPTION(OPTION, IF-SET, [IF-NOT-SET])
# -------------------------------------------
# Execute IF-SET if OPTION is set, IF-NOT-SET otherwise.
AC_DEFUN([_AM_IF_OPTION],
[m4_ifset(_AM_MANGLE_OPTION([$1]), [$2], [$3])])

# Check to make sure that the build environment is sane.    -*- Autoconf -*-

# Copyright (C) 1996-2021 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# AM_SANITY_CHECK
# ---------------
AC_DEFUN([AM_SANITY_CHECK],
[AC_MSG_CHECKING([whether build environment is sane])
# Reject unsafe characters in $srcdir or the absolute working directory
# name.  Accept space and tab only in the latter.
am_lf='
'
case `pwd` in
  *[[\\\"\#\$\&\'\`$am_lf]]*)
    AC_MSG_ERROR([unsafe absolute working directory name]);;
esac
case $srcdir in
  *[[\\\"\#\$\&\'\`$am_lf\ \	]]*)
    AC_MSG_ERROR([unsafe srcdir value: '$srcdir']);;
esac

# Do 'set' in a subshell so we don't clobber the current shell's
# arguments.  Must try -L first in case configure is actually a
# symlink; some systems play weird games with the mod time of symlinks
# (eg FreeBSD returns the mod time of the symlink's containing
# directory).
if (
   am_has_slept=no
   for am_try in 1 2; do
     echo "timestamp, slept: $am_has_slept" > conftest.file
     set X `ls -Lt "$srcdir/configure" conftest.file 2> /dev/null`
     if test "$[*]" = "X"; then
	# -L didn't work.
	set X `ls -t "$srcdir/configure" conftest.file`
     fi
     if test "$[*]" != "X $srcdir/configure conftest.file" \
	&& test "$[*]" != "X conftest.file $srcdir/configure"; then

	# If neither matched, then we have a broken ls.  This can happen
	# if, for instance, CONFIG_SHELL is bash and it inherits a
	# broken ls alias from the environment.  This has actually
	# happened.  Such a system could not be considered "sane".
	AC_MSG_ERROR([ls -t appears to fail.  Make sure there is not a broken
  alias in your environment])
     fi
     if test "$[2]" = conftest.file || test $am_try -eq 2; then
       break
     fi
     # Just in case.
     sleep 1
     am_has_slept=yes
   done
   test "$[2]" = conftest.file
   )
then
   # Ok.
   :
else
   AC_MSG_ERROR([newly created file is older than distributed files!
Check your system clock])
fi
AC_MSG_RESULT([yes])
# If we didn't sleep, we still need to ensure time stamps of config.status and
# generated files are strictly newer.
am_sleep_pid=
if grep 'slept: no' conftest.file >/dev/null 2>&1; then
  ( sleep 1 ) &
  am_sleep_pid=$!
fi
AC_CONFIG_COMMANDS_PRE(
  [AC_MSG_CHECKING([that generated files are newer than configure])
   if test -n "$am_sleep_pid"; then
     # Hide warnings about reused PIDs.
     wait $am_sleep_pid 2>/dev/null
   fi
   AC_MSG_RESULT([done])])
rm -f conftest.file
])

# Copyright (C) 2009-2021 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# AM_SILENT_RULES([DEFAULT])
# --------------------------
# Enable less verbose build rules; with the default set to DEFAULT
# ("yes" being less verbose, "no" or empty being verbose).
AC_DEFUN([AM_SILENT_RULES],
[AC_ARG_ENABLE([silent-rules], [dnl
AS_HELP_STRING(
  [--enable-silent-rules],
  [less verbose build output (undo: "make V=1")])
AS_HELP_STRING(
  [--disable-silent-rules],
  [verbose build output (undo: "make V=0")])dnl
])
case $enable_silent_rules in @%:@ (((
  yes) AM_DEFAULT_VERBOSITY=0;;
   no) AM_DEFAULT_VERBOSITY=1;;
    *) AM_DEFAULT_VERBOSITY=m4_if([$1], [yes], [0], [1]);;
esac
dnl
dnl A few 'make' implementations (e.g., NonStop OS and NextStep)
dnl do not support nested variable expansions.
dnl See automake bug#9928 and bug#10237.
am_make=${MAKE-make}
AC_CACHE_CHECK([whether $am_make supports nested variables],
   [am_cv_make_support_nested_variables],
   [if AS_ECHO([['TRUE=$(BAR$(V))
BAR0=false
BAR1=true
V=1
am__doit:
	@$(TRUE)
.PHONY: am__doit']]) | $am_make -f - >/dev/null 2>&1; then
  am_cv_make_support_nested_variables=yes
else
  am_cv_make_support_nested_variables=no
fi])
if test $am_cv_make_support_nested_variables = yes; then
  dnl Using '$V' instead of '$(V)' breaks IRIX make.
  AM_V='$(V)'
  AM_DEFAULT_V='$(AM_DEFAULT_VERBOSITY)'
else
  AM_V=$AM_DEFAULT_VERBOSITY
  AM_DEFAULT_V=$AM_DEFAULT_VERBOSITY
fi
AC_SUBST([AM_V])dnl
AM_SUBST_NOTMAKE([AM_V])dnl
AC_SUBST([AM_DEFAULT_V])dnl
AM_SUBST_NOTMAKE([AM_DEFAULT_V])dnl
AC_SUBST([AM_DEFAULT_VERBOSITY])dnl
AM_BACKSLASH='\'
AC_SUBST([AM_BACKSLASH])dnl
_AM_SUBST_NOTMAKE([AM_BACKSLASH])dnl
])

# Copyright (C) 2001-2021 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# AM_PROG_INSTALL_STRIP
# ---------------------
# One issue with vendor 'install' (even GNU) is that you can't
# specify the program used to strip binaries.  This is especially
# annoying in cross-compiling environments, where the build's strip
# is unlikely to handle the host's binaries.
# Fortunately install-sh will honor a STRIPPROG variable, so we
# always use install-sh in "make install-strip", and initialize
# STRIPPROG with the value of the STRIP variable (set by the user).
AC_DEFUN([AM_PROG_INSTALL_STRIP],
[AC_REQUIRE([AM_PROG_INSTALL_SH])dnl
# Installed binaries are usually stripped using 'strip' when the user
# run "make install-strip".  However 'strip' might not be the right
# tool to use in cross-compilation environments, therefore Automake
# will honor the 'STRIP' environment variable to overrule this program.
dnl Don't test for $cross_compiling = yes, because it might be 'maybe'.
if test "$cross_compiling" != no; then
  AC_CHECK_TOOL([STRIP], [strip], :)
fi
INSTALL_STRIP_PROGRAM="\$(install_sh) -c -s"
AC_SUBST([INSTALL_STRIP_PROGRAM])])

# Copyright (C) 2006-2021 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# _AM_SUBST_NOTMAKE(VARIABLE)
# ---------------------------
# Prevent Automake from outputting VARIABLE = @VARIABLE@ in Makefile.in.
# This macro is traced by Automake.
AC_DEFUN([_AM_SUBST_NOTMAKE])

# AM_SUBST_NOTMAKE(VARIABLE)
# --------------------------
# Public sister of _AM_SUBST_NOTMAKE.
AC_DEFUN([AM_SUBST_NOTMAKE], [_AM_SUBST_NOTMAKE($@)])

# Check how to create a tarball.                            -*- Autoconf -*-

# Copyright (C) 2004-2021 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# _AM_PROG_TAR(FORMAT)
# --------------------
# Check how to create a tarball in format FORMAT.
# FORMAT should be one of 'v7', 'ustar', or 'pax'.
#
# Substitute a variable $(am__tar) that is a command
# writing to stdout a FORMAT-tarball containing the directory
# $tardir.
#     tardir=directory && $(am__tar) > result.tar
#
# Substitute a variable $(am__untar) that extract such
# a tarball read from stdin.
#     $(am__untar) < result.tar
#
AC_DEFUN([_AM_PROG_TAR],
[# Always define AMTAR for backward compatibility.  Yes, it's still used
# in the wild :-(  We should find a proper way to deprecate it ...
AC_SUBST([AMTAR], ['$${TAR-tar}'])

# We'll loop over all known methods to create a tar archive until one works.
_am_tools='gnutar m4_if([$1], [ustar], [plaintar]) pax cpio none'

m4_if([$1], [v7],
  [am__tar='$${TAR-tar} chof - "$$tardir"' am__untar='$${TAR-tar} xf -'],

  [m4_case([$1],
    [ustar],
     [# The POSIX 1988 'ustar' format is defined with fixed-size fields.
      # There is notably a 21 bits limit for the UID and the GID.  In fact,
      # the 'pax' utility can hang on bigger UID/GID (see automake bug#8343
      # and bug#13588).
      am_max_uid=2097151 # 2^21 - 1
      am_max_gid=$am_max_uid
      # The $UID and $GID variables are not portable, so we need to resort
      # to the POSIX-mandated id(1) utility.  Errors in the 'id' calls
      # below are definitely unexpected, so allow the users to see them
      # (that is, avoid stderr redirection).
      am_uid=`id -u || echo unknown`
      am_gid=`id -g || echo unknown`
      AC_MSG_CHECKING([whether UID '$am_uid' is supported by ustar format])
      if test $am_uid -le $am_max_uid; then
         AC_MSG_RESULT([yes])
      else
         AC_MSG_RESULT([no])
         _am_tools=none
      fi
      AC_MSG_CHECKING([whether GID '$am_gid' is supported by ustar format])
      if test $am_gid -le $am_max_gid; then
         AC_MSG_RESULT([yes])
      else
        AC_MSG_RESULT([no])
        _am_tools=none
      fi],

  [pax],
    [],

  [m4_fatal([Unknown tar format])])

  AC_MSG_CHECKING([how to create a $1 tar archive])

  # Go ahead even if we have the value already cached.  We do so because we
  # need to set the values for the 'am__tar' and 'am__untar' variables.
  _am_tools=${am_cv_prog_tar_$1-$_am_tools}

  for _am_tool in $_am_tools; do
    case $_am_tool in
    gnutar)
      for _am_tar in tar gnutar gtar; do
        AM_RUN_LOG([$_am_tar --version]) && break
      done
      am__tar="$_am_tar --format=m4_if([$1], [pax], [posix], [$1]) -chf - "'"$$tardir"'
      am__tar_="$_am_tar --format=m4_if([$1], [pax], [posix], [$1]) -chf - "'"$tardir"'
      am__untar="$_am_tar -xf -"
      ;;
    plaintar)
      # Must skip GNU tar: if it does not support --format= it doesn't create
      # ustar tarball either.
      (tar --version) >/dev/null 2>&1 && continue
      am__tar='tar chf - "$$tardir"'
      am__tar_='tar chf - "$tardir"'
      am__untar='tar xf -'
      ;;
    pax)
      am__tar='pax -L -x $1 -w "$$tardir"'
      am__tar_='pax -L -x $1 -w "$tardir"'
      am__untar='pax -r'
      ;;
    cpio)
      am__tar='find "$$tardir" -print | cpio -o -H $1 -L'
      am__tar_='find "$tardir" -print | cpio -o -H $1 -L'
      am__untar='cpio -i -H $1 -d'
      ;;
    none)
      am__tar=false
      am__tar_=false
      am__untar=false
      ;;
    esac

    # If the value was cached, stop now.  We just wanted to have am__tar
    # and am__untar set.
    test -n "${am_cv_prog_tar_$1}" && break

    # tar/untar a dummy directory, and stop if the command works.
    rm -rf conftest.dir
    mkdir conftest.dir
    echo GrepMe > conftest.dir/file
    AM_RUN_LOG([tardir=conftest.dir && eval $am__tar_ >conftest.tar])
    rm -rf conftest.dir
    if test -s conftest.tar; then
      AM_RUN_LOG([$am__untar <conftest.tar])
      AM_RUN_LOG([cat conftest.dir/file])
      grep GrepMe conftest.dir/file >/dev/null 2>&1 && break
    fi
  done
  rm -rf conftest.dir

  AC_CACHE_VAL([am_cv_prog_tar_$1], [am_cv_prog_tar_$1=$_am_tool])
  AC_MSG_RESULT([$am_cv_prog_tar_$1])])

AC_SUBST([am__tar])
AC_SUBST([am__untar])
]) # _AM_PROG_TAR

# LB_CHECK_FILE
#
# Check for file existance even when cross compiling
#
AC_DEFUN([LB_CHECK_FILE],
[AS_VAR_PUSHDEF([lb_File], [lb_cv_file_$1])dnl
AC_CACHE_CHECK([for $1], lb_File,
[if test -r "$1"; then
    AS_VAR_SET(lb_File, yes)
else
    AS_VAR_SET(lb_File, no)
fi])
AS_IF([test AS_VAR_GET(lb_File) = yes], [$2], [$3])[]dnl
AS_VAR_POPDEF([lb_File])dnl
])# LB_CHECK_FILE

# LB_ARG_REPLACE_PATH(PACKAGE, PATH)
AC_DEFUN([LB_ARG_REPLACE_PATH],[
	new_configure_args=
	eval "set x $ac_configure_args"
	shift
	for arg; do
		case $arg in
			--with-[$1]=*)
				arg=--with-[$1]=[$2]
				;;
			*\'*)
				arg=$(printf %s\n ["$arg"] | \
				      sed "s/'/'\\\\\\\\''/g")
				;;
		esac
		dnl AS_VAR_APPEND([new_configure_args], [" '$arg'"])
		new_configure_args="$new_configure_args \"$arg\""
	done
	ac_configure_args=$new_configure_args
])

# this is the work-horse of the next function
AC_DEFUN([__LB_ARG_CANON_PATH], [
	[$3]=$(readlink -f $with_$2)
	LB_ARG_REPLACE_PATH([$1], $[$3])
])

# a front-end for the above function that transforms - and . in the
# PACKAGE portion of --with-PACKAGE into _ suitable for variable names
AC_DEFUN([LB_ARG_CANON_PATH], [
	__LB_ARG_CANON_PATH([$1], m4_translit([$1], [-.], [__]), [$2])
])

#
#
# LB_LINUX_PATH
#
# Find paths for linux, handling kernel-source rpms
#
AC_DEFUN([LB_LINUX_PATH],
[# prep some default values
for DEFAULT_LINUX in /lib/modules/$(uname -r)/{source,build} /usr/src/linux; do
	if readlink -q -e $DEFAULT_LINUX >/dev/null; then
		break
	fi
done
if test "$DEFAULT_LINUX" = "/lib/modules/$(uname -r)/source"; then
	PATHS="/lib/modules/$(uname -r)/build"
fi
PATHS="$PATHS $DEFAULT_LINUX"
for DEFAULT_LINUX_OBJ in $PATHS; do
	if readlink -q -e $DEFAULT_LINUX_OBJ >/dev/null; then
		break
	fi
done
AC_MSG_CHECKING([for Linux sources])
AC_ARG_WITH([linux],
	AS_HELP_STRING([--with-linux=path],
		       [set path to Linux source (default=/lib/modules/$(uname -r)/{source,build},/usr/src/linux)]),
	[LB_ARG_CANON_PATH([linux], [LINUX])
	DEFAULT_LINUX_OBJ=$LINUX],
	[LINUX=$DEFAULT_LINUX])
AC_MSG_RESULT([$LINUX])
AC_SUBST(LINUX)

# -------- check for linux --------
LB_CHECK_FILE([$LINUX],[],
	[AC_MSG_ERROR([Kernel source $LINUX could not be found.])])

# -------- linux objects (for 2.6) --
AC_MSG_CHECKING([for Linux objects dir])
AC_ARG_WITH([linux-obj],
	AS_HELP_STRING([--with-linux-obj=path],
			[set path to Linux objects dir (default=/lib/modules/$(uname -r)/build,/usr/src/linux)]),
	[LB_ARG_CANON_PATH([linux-obj], [LINUX_OBJ])],
	[LINUX_OBJ=$DEFAULT_LINUX_OBJ])

AC_MSG_RESULT([$LINUX_OBJ])
AC_SUBST(LINUX_OBJ)

# -------- check for .config --------
AC_ARG_WITH([linux-config],
	[AS_HELP_STRING([--with-linux-config=path],
			[set path to Linux .conf (default=$LINUX_OBJ/include/config/auto.conf)])],
	[LB_ARG_CANON_PATH([linux-config], [LINUX_CONFIG])],
	[LINUX_CONFIG=$LINUX_OBJ/include/config/auto.conf])
AC_SUBST(LINUX_CONFIG)

LB_CHECK_FILE([/boot/kernel.h],
	[KERNEL_SOURCE_HEADER='/boot/kernel.h'],
	[LB_CHECK_FILE([/var/adm/running-kernel.h],
		[KERNEL_SOURCE_HEADER='/var/adm/running-kernel.h'])])

AC_ARG_WITH([kernel-source-header],
	AS_HELP_STRING([--with-kernel-source-header=path],
			[Use a different kernel version header.  Consult build/README.kernel-source for details.]),
	[LB_ARG_CANON_PATH([kernel-source-header], [KERNEL_SOURCE_HEADER])])

# ------------ .config exists ----------------
LB_CHECK_FILE([$LINUX_CONFIG],[],
	[AC_MSG_ERROR([Kernel config could not be found.  If you are building from a kernel-source rpm consult build/README.kernel-source])])

]) # end of LB_LINUX_PATH

# Copy over the same logic that DKMS uses to set LLVM=1 if kernel was
# built with LLVM, because this code is run in a pre-script of dkms.conf
# and therefore will not get the extra LLVM=1 dkms sets in the make command.
AC_DEFUN([LB_IS_LLVM],
	[AC_MSG_CHECKING([kernel built with clang])
	_lb_is_clang=no
	if test -f "$LINUX_OBJ/include/generated/autoconf.h"; then
		if grep -q 2>/dev/null "define CONFIG_CLANG_VERSION 1"  "$LINUX_OBJ/include/generated/autoconf.h"; then
			_lb_is_clang="yes"
		fi
	elif test -f "$LINUX_OBJ/.config"; then
		if grep -q 2>/dev/null CONFIG_CC_IS_CLANG=y "$LINUX_OBJ/.config"; then
			_lb_is_clang="yes"
		fi
	elif test -f "$LINUX_OBJ/vmlinux"; then
		if readelf -p .comment "$LINUX_OBJ/vmlinux" 2>&1 | grep -q clang; then
			_lb_is_clang="yes"
		fi
	fi
	if test "$_lb_is_clang" = "yes"; then
		export LLVM=1
	fi
	AC_MSG_RESULT($_lb_is_clang)
])

# LB_LINUX_SYMVERFILE
# SLES 9 uses a different name for this file - unsure about vanilla kernels
# around this version, but it matters for servers only.
AC_DEFUN([LB_LINUX_SYMVERFILE],
	[AC_MSG_CHECKING([name of module symbol version file])
	if grep -q Modules.symvers $LINUX/scripts/Makefile.modpost ; then
		SYMVERFILE=Modules.symvers
	else
		SYMVERFILE=Module.symvers
	fi
	AC_MSG_RESULT($SYMVERFILE)
	AC_SUBST(SYMVERFILE)
])

#
# LB_CHECK_SYMBOL_EXPORT
# check symbol exported or not
# $1 - symbol
# $2 - file(s) for find.
# $3 - do 'yes'
# $4 - do 'no'
#
# 2.6 based kernels - put modversion info into $LINUX_OBJ/Module.modvers
# or check
AC_DEFUN([LB_CHECK_SYMBOL_EXPORT],
[AC_MSG_CHECKING([if Linux was built with symbol $1 exported])
grep -q -E '[[[:space:]]]$1[[[:space:]]]' $LINUX_OBJ/$SYMVERFILE 2>/dev/null
rc=$?
if test $rc -ne 0; then
	export=0
	for file in $2; do
		grep -q -E "EXPORT_SYMBOL.*\($1\)" "$LINUX/$file" 2>/dev/null
		rc=$?
		if test $rc -eq 0; then
			export=1
			break;
		fi
	done
	if test $export -eq 0; then
		AC_MSG_RESULT([no])
		$4
	else
		AC_MSG_RESULT([yes])
		$3
	fi
else
	AC_MSG_RESULT([yes])
	$3
fi
])

/nl Examine kernel functionality

AC_DEFUN([MLNX_RDMA_SET_GLOBALS],
[
	MLNX_RDMA_MODULES_DIR="$PWD/modtest"
	MLNX_RDMA_TEST_MOD="testmod"
	MLNX_RDMA_RUN_LOG="$MLNX_RDMA_MODULES_DIR/run.log"
	# Generally handle any warning as error (-Werror), except:
	# -Wno-unused-variable: A common pattern is to initialize a
	# 		         variable to make sure e.g. a field exists
	# 			 but not bother using it later.
	# -Wno-uninitialized: A common pattern in tests is to use
	# 		      uninitialized values, so we won't have to
	# 		      worry about their type.
	# -Wno-missing-braces: Harmless and almost always wrong
	ERROR_FLAGS="-Werror -Wno-unused-variable -Wno-unused-value -Wno-uninitialized -Wno-missing-braces"
])

AC_DEFUN([MLNX_RDMA_TEST_CASE],
[
	if false; then
		AC_DEFINE($1, -1, [$2])
	fi
	MLNX_RDMA_MOD_NAME=$1
	MLNX_RDMA_MOD_DIR="$MLNX_RDMA_MODULES_DIR/$MLNX_RDMA_MOD_NAME"
	rm -rf "$MLNX_RDMA_MOD_DIR"
	mkdir -p "$MLNX_RDMA_MOD_DIR"
	cat <<'EOF' >"$MLNX_RDMA_MOD_DIR/$MLNX_RDMA_TEST_MOD.c"
#include <linux/module.h>
#include <linux/kernel.h>
MODULE_LICENSE("GPL");
$3
static int __maybe_unused test_func (void) {
$4
	return 0;
}
EOF
	dnl FIXME: Silence the dots when autoconf is in quiet mode:
	cat <<EOF >"$MLNX_RDMA_MOD_DIR/Makefile"
obj-m += $MLNX_RDMA_TEST_MOD.o
# The rest is for printing a single dot:
ifeq (,\$(MLNX_RDMA_SILENT))
\$(obj)/$MLNX_RDMA_TEST_MOD.o: \$(obj)/echo
\$(obj)/echo:
	@echo -n .
.PHONY: \$(obj)/echo
endif
EOF
	echo "obj-\$(MLNX_TEST)\$(MLNX_TEST_$MLNX_RDMA_MOD_NAME) += $MLNX_RDMA_MOD_NAME/" >>$MLNX_RDMA_MODULES_DIR/Makefile
	echo "$2" > "$MLNX_RDMA_MODULES_DIR/desc"
])

AC_DEFUN([MLNX_RDMA_BUILD_MODULES],
[
	AC_MSG_NOTICE([Test-building kernel modules test-builds])
	make -s -C "$LINUX_OBJ" -k -j${NJOBS:-1} ccflags-y="$ERROR_FLAGS" "M=$MLNX_RDMA_MODULES_DIR" MLNX_TEST=m MLNX_RDMA_SILENT=$silent modules 2>"$MLNX_RDMA_RUN_LOG"
	echo '' # FIXME: Silence in quiet mode
])

AC_DEFUN([MLNX_RDMA_CHECK_RESULTS],
[
	AC_MSG_CHECKING([for results from kernel modules test-builds])
	for mlnx_rdma_mod_dir in $MLNX_RDMA_MODULES_DIR/HAVE_*; do
		if test ! -d "$mlnx_rdma_mod_dir"; then continue; fi
		mlnx_rdma_mod_dir_name="${mlnx_rdma_mod_dir##*/}"
		test ! -e "$mlnx_rdma_mod_dir/$MLNX_RDMA_TEST_MOD.o"
		mlnx_rdma_mod_dir_rc=$?
		if test "$mlnx_rdma_mod_dir_rc" = 1; then
			AC_DEFINE_UNQUOTED([$mlnx_rdma_mod_dir_name], [$mlnx_rdma_mod_dir_rc])
		fi
	done
	AC_MSG_RESULT([done])
])

AC_DEFUN([MLNX_RDMA_CHECK_BUILD_SANITY],
[
	AC_MSG_CHECKING([for a working kernel modules build system])
	MLNX_RDMA_TEST_CASE(KBUILD_WORKS, [building a kernel module works], [
	],[
	])
	make -s -C "$LINUX_OBJ" ccflags-y="$ERROR_FLAGS" "M=$MLNX_RDMA_MODULES_DIR" MLNX_TEST_KBUILD_WORKS=m MLNX_RDMA_SILENT=yes modules 2>"$MLNX_RDMA_RUN_LOG"
	mlnx_ofed_rc=$?
	if test "$mlnx_ofed_rc" != 0; then
		echo ''; cat "$MLNX_RDMA_RUN_LOG"
		AC_MSG_ERROR([Failed to build a dummy kernel module. Check compiler, kernel headers, etc.])
	fi
	AC_MSG_RESULT([yes])
])

AC_DEFUN([MLNX_RDMA_CREATE_MODULES],
[
	rm -rf ${MLNX_RDMA_MODULES_DIR}
	mkdir -p ${MLNX_RDMA_MODULES_DIR}

	MLNX_RDMA_CHECK_BUILD_SANITY

	MLNX_RDMA_TEST_CASE(HAVE_NDO_LOCK_STATUS_GET_GET_ERROR_STATUS, [dpll_pin_ops.lock_status_get has status_error], [
		#include <linux/dpll.h>

		int my_lock_status_get(const struct dpll_device *dpll, void *dpll_priv,
						enum dpll_lock_status *status,
						enum dpll_lock_status_error *status_error,
						struct netlink_ext_ack *extack);
		int my_lock_status_get(const struct dpll_device *dpll, void *dpll_priv,
		                               enum dpll_lock_status *status,
                		               enum dpll_lock_status_error *status_error,
                               		       struct netlink_ext_ack *extack)
		{
			return 0;
		}
	],[
		struct dpll_device_ops ndops = {
			.lock_status_get = my_lock_status_get,
		};

		return 0;
	])

	   MLNX_RDMA_TEST_CASE(HAVE_NET_DIM_POINTER_END_SAMPLE, [net_dim get const pointer end_sample], [
		      #include <linux/dim.h>
	],[
		      struct dim_sample dim_sample = {};
	              net_dim(NULL, &dim_sample);
		      return 0;
	 ])

	MLNX_RDMA_TEST_CASE(HAVE_DPLL_STRUCTS, [have struct dpll_pin_ops], [
	#include <linux/dpll.h>
	],[
		struct dpll_pin_ops *pin_ops = NULL;
		struct dpll_device_ops *devce_ops = NULL;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DPLL_PIN_OPS_HAS_FFO_GET, [struct dpll_pin_ops has ffo_get], [
	#include <linux/dpll.h>
	],[
		struct dpll_pin_ops pin_ops;

		pin_ops.ffo_get = NULL;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DPLL_NETDEV_PIN_SET, [dpll.h has dpll_netdev_pin_set], [
	#include <linux/dpll.h>
	],[
		dpll_netdev_pin_set(NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NETDEV_DPLL_PIN_SET, [netdevice.h has netdev_dpll_pin_set], [
	#include <linux/netdevice.h>
	],[
		netdev_dpll_pin_set(NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_CLOCK_QUALITY_LEVEL_GET, [have function clock_quality_level_get], [
	#include <linux/dpll.h>
	static int foo_clock_quality_level_get(const struct dpll_device *dpll,
						void *priv,
						unsigned long *qls,
						struct netlink_ext_ack *extack)
		{
			return 0;
		}

	],[
		static struct dpll_device_ops ddo = {
			.clock_quality_level_get = foo_clock_quality_level_get,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_KVFREE_IN_SLAB_H, [kvfree prototype is in slab.h], [
		#include <linux/slab.h>
	],[
		kvfree(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SLAB_NO_OBJ_EXT, [SLAB_NO_OBJ_EXT is defined], [
		#include <linux/slab.h>
	],[
		#ifdef SLAB_NO_OBJ_EXT
			return 0;
		#else
			#return 1
		#endif
	])

	MLNX_RDMA_TEST_CASE(HAVE_HMM_PFN_TO_PAGE, [have hmm_pfn_to_page], [
	#include <linux/hmm.h>
	],[
		hmm_pfn_to_page(0UL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_HMM_PFN_TO_MAP_ORDER, [have hmm_pfn_to_map_order], [
	#include <linux/hmm.h>
	],[
		unsigned int i = hmm_pfn_to_map_order(0UL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_VM_FLAGS_CLEAR, [vm_flags_clear exists], [
	#include <linux/hmm.h>
	],[
		vm_flags_clear(NULL, 0);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_HMM_RANGE_HAS_HMM_PFNS, [hmm_range has hmm_pfns], [
	#include <linux/hmm.h>
	],[
		struct hmm_range h;
		h.hmm_pfns = NULL;
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_HMM_RANGE_FAULT_HAS_ONE_PARAM, [hmm_range_fault has one param], [
	#include <linux/hmm.h>
	],[
		int l;
		l = hmm_range_fault(NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_UDP_TUNNEL_NIC_INFO_STATIC_IANA_VXLAN, [udp_tunnel.h has enum UDP_TUNNEL_NIC_INFO_STATIC_IANA_VXLAN], [
	#include <net/udp_tunnel.h>
	],[
		int flag;

		flag = UDP_TUNNEL_NIC_INFO_STATIC_IANA_VXLAN;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_UDP_TUNNEL_NIC_INFO, [udp_tunnel.h has struct udp_tunnel_nic_info is defined], [
	#include <net/udp_tunnel.h>
	],[
		struct udp_tunnel_nic_info x;

		return 0;
	])

	dnl text should be: linux/netdevice.h has netdev_hold and netdev_put
	MLNX_RDMA_TEST_CASE(HAVE_NETDEV_PUT_AND_HOLD, [linux/netdevice.h has netdev_hold], [
	#include <linux/netdevice.h>
	],[
		netdev_hold(NULL,NULL, 0);
		netdev_put(NULL,NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_UNREGISTER_NETDEVICE_NOTIFIER_NET, [unregister_netdevice_notifier_net is defined], [
	#include <linux/netdevice.h>
	],[
		unregister_netdevice_notifier_net(NULL,NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_REGISTER_NETDEVICE_NOTIFIER_DEV_NET, [register_netdevice_notifier_dev_net is defined], [
	#include <linux/netdevice.h>
	],[
		register_netdevice_notifier_dev_net(NULL,NULL,NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NETIF_NAPI_ADD_CONFIG, [netdevice.h has netif_napi_add_config], [
        #include <linux/netdevice.h>
	],[
        	netif_napi_add_config(NULL, NULL, NULL ,0);

	        return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEV_XDP_PROG_ID, [dev_xdp_prog_id is defined], [
	#include <linux/netdevice.h>
	],[
		dev_xdp_prog_id(NULL,0);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NETDEV_NET_NOTIFIER, [struct netdev_net_notifier is defined], [
	#include <linux/netdevice.h>
	],[
		struct netdev_net_notifier notifier;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NET_PREFETCH, [net_prefetch is defined], [
	#include <linux/netdevice.h>
	],[
		net_prefetch(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_IS_COW_MAPPING, [is_cow_mapping is defined], [
		#include <linux/mm.h>
	],[
		is_cow_mapping(0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_GET_USER_PAGES_LONGTERM, [get_user_pages_longterm is defined], [
		#include <linux/mm.h>
	],[
		get_user_pages_longterm(0, 0, 0, NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_GET_USER_PAGES_4_PARAMS, [get_user_pages has 4 params], [
		#include <linux/mm.h>
	],[
		get_user_pages(0, 0, 0, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_GET_USER_PAGES_5_PARAMS, [get_user_pages has 5 params], [
		#include <linux/mm.h>
	],[
		get_user_pages(0, 0, 0, NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_GET_USER_PAGES_7_PARAMS, [get_user_pages has 7 params], [
		#include <linux/mm.h>
	],[
		get_user_pages(NULL, NULL, 0, 0, 0, NULL, NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_MMAP_READ_LOCK, [map_lock has mmap_read_lock], [
	#include <linux/mm.h>
	],[
		mmap_read_lock(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_GET_USER_PAGES_REMOTE_7_PARAMS_AND_SECOND_INT, [get_user_pages_remote is defined with 7 parameters and parameter 2 is integer], [
	#include <linux/mm.h>
	],[
		get_user_pages_remote(NULL, 0, 0, 0, NULL, NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_GET_USER_PAGES_REMOTE_8_PARAMS, [get_user_pages_remote is defined with 8 parameters], [
	#include <linux/mm.h>
	],[
		get_user_pages_remote(NULL, NULL, 0, 0, 0, 0, NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_GET_USER_PAGES_REMOTE_8_PARAMS_W_LOCKED, [get_user_pages_remote is defined with 8 parameters with locked], [
	#include <linux/mm.h>
	],[
		get_user_pages_remote(NULL, NULL, 0, 0, 0, NULL, NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_INT_POW, [int_pow defined], [
		#include <linux/kernel.h>
	],[
		return int_pow(2, 3);

	])

	MLNX_RDMA_TEST_CASE(HAVE_GET_RANDOM_U32_INCLUSIVE, [get_random_u32_inclusive defined], [
		#include <linux/random.h>
	],[
		int a;
		a = get_random_u32_inclusive(0, 100);

	])

	MLNX_RDMA_TEST_CASE(HAVE_GET_RANDOM_U8, [get_random_u8 defined], [
		#include <linux/random.h>
	],[
		int a;
		a = get_random_u8();

	])

	MLNX_RDMA_TEST_CASE(HAVE_NDO_GET_DEVLINK_PORT, [ndo_get_devlink_port is defined], [
		#include <linux/netdevice.h>
	],[
		struct net_device_ops ndops = {
			.ndo_get_devlink_port = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_INT_DEVLINK_FMSG_U8_PAIR, [devlink_fmsg_u8_pair_put returns int], [
		#include <net/devlink.h>
	],[
		int err = devlink_fmsg_u8_pair_put(NULL, "test", 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_IPSEC_CRYPTO, [port_fn_ipsec_crypto_get is defined], [
		#include <net/devlink.h>
	],[
		struct devlink_port_ops dl_port_ops  = {
			.port_fn_ipsec_crypto_get = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_IPSEC_PACKET, [port_fn_ipsec_packet_get is defined], [
		#include <net/devlink.h>
	],[
		struct devlink_port_ops dl_port_ops  = {
			.port_fn_ipsec_packet_get = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_INSTANCES_RELATIONSHIPS_EXPOSURE, [kernel supports v6.7 devlink instances relationships exposure], [
		#include <net/devlink.h>
	],[
		struct devlink_port dp;
		enum devlink_port_function_attr attr;

		dp.rel_index = 2;
		attr = DEVLINK_PORT_FN_ATTR_DEVLINK;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XDP_METADATA_OPS, [struct net_device has struct net_device has xdp_metadata_ops member], [
		#include <linux/netdevice.h>
	],[
		struct net_device nd = {
			.xdp_metadata_ops = NULL,
		};

		return 0;
	])

       MLNX_RDMA_TEST_CASE(HAVE_QUEUE_AND_NAPI_ASSOCIATION, [kernel supports queue and napi association], [
               #include <net/netdev_rx_queue.h>
       ],[
               struct napi_struct ns;
               struct netdev_rx_queue nrq;

               ns.irq = 2;
               nrq.napi = NULL;

               return 0;
       ])

	MLNX_RDMA_TEST_CASE(HAVE_DEVL_RATE_LEAF_CREATE_GET_3_PARAMS, [devl_rate_leaf_create 3 param], [
		#include <net/devlink.h>
	],[
		devl_rate_leaf_create(NULL, NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_INFO_VERSION_FIXED_PUT, [devlink_info_version_fixed_put exist], [
		#include <net/devlink.h>
	],[
		devlink_info_version_fixed_put(NULL, NULL, NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_PORT_TYPE_ETH_SET_GET_1_PARAM, [devlink_port_type_eth_set get 1 param], [
		#include <net/devlink.h>
	],[
		devlink_port_type_eth_set(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVL_PARAM_DRIVERINIT_VALUE_GET, [devlink.h has devl_param_driverinit_value_get], [
		#include <net/devlink.h>
	],[
		devl_param_driverinit_value_get(NULL, 0, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVL_PORT_HEALTH_REPORTER_CREATE, [devlink.h has devl_port_health_reporter_create], [
		#include <net/devlink.h>
	],[
		devl_port_health_reporter_create(NULL, NULL, 0, NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVL_HEALTH_REPORTER_CREATE, [devlink.h has devl_health_reporter_create], [
		#include <net/devlink.h>
	],[
		devl_health_reporter_create(NULL, NULL, 0, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_INFO_DRIVER_NAME_PUT, [devlink.h has devlink_info_driver_name_put], [
		#include <net/devlink.h>
	],[
		devlink_info_driver_name_put(NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_SET_FEATURES, [devlink.h has devlink_set_features], [
		#include <net/devlink.h>
	],[
		devlink_set_features(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_TO_DEV, [devlink.h has devlink_to_dev], [
		#include <net/devlink.h>
	],[
		devlink_to_dev(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVL_PORT_REGISTER, [devlink.h devl_port_register defined], [
		#include <net/devlink.h>
	],[
		devl_port_register(NULL, NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVL_TRAP_GROUPS_REGISTER, [devlink.h devl_trap_groups_register defined], [
		#include <net/devlink.h>
	],[
		devl_trap_groups_register(NULL, NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_PARAM_REGISTER, [devlink.h devlink_param_register defined], [
		#include <net/devlink.h>
	],[
		devlink_param_register(NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_REGISTER_GET_1_PARAMS, [devlink.h has devlink_register get 1 params], [
		#include <net/devlink.h>
	],[
		devlink_register(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVL_REGISTER, [devlink.h has devl_register], [
		#include <net/devlink.h>
	],[
		devl_register(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVL_RESOURCE_REGISTER, [devlink.h has devl_resource_register], [
		#include <net/devlink.h>
	],[
		devl_resource_register(NULL, NULL, 0, 0, 0, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVL_RESOURCES_UNREGISTER, [devlink.h has devl_resources_unregister], [
		#include <net/devlink.h>
	],[
		devl_resources_unregister(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_RESOURCES_UNREGISTER_2_PARAMS, [devlink.h has devlink_resources_unregister 2 params], [
		#include <net/devlink.h>
	],[
		devlink_resources_unregister(NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_RESOURCES_UNREGISTER_1_PARAMS, [devlink.h has devlink_resources_unregister 1 params], [
		#include <net/devlink.h>
	],[
		devlink_resources_unregister(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_ALLOC_GET_3_PARAMS, [devlink.h has devlink_alloc get 3 params], [
		#include <net/devlink.h>
	],[
		devlink_alloc(NULL, 0, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_PORT_ATTRS_PCI_SF_SET_GET_4_PARAMS, [devlink.h has devlink_port_attrs_pci_sf_set get 4 params], [
		#include <net/devlink.h>
	],[
		devlink_port_attrs_pci_sf_set(NULL, 0, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_PORT_ATTRS_PCI_SF_SET_GET_5_PARAMS, [devlink.h has devlink_port_attrs_pci_sf_set get 5 params], [
		#include <net/devlink.h>
	],[
		devlink_port_attrs_pci_sf_set(NULL, 0, 0, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_PORT_ATTRS_PCI_VF_SET_GET_3_PARAMS, [devlink.h devlink_port_attrs_pci_vf_set get 3 params], [
		#include <net/devlink.h>
	],[
		devlink_port_attrs_pci_vf_set(NULL, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_PORT_ATTRS_PCI_VF_SET_GET_5_PARAMS, [devlink_port_attrs_pci_vf_set has 5 params], [
		#include <net/devlink.h>
	],[
		devlink_port_attrs_pci_vf_set(NULL, NULL, 0, 0, 0);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_PORT_ATTRS_PCI_VF_SET_GET_CONTROLLER_NUM, [devlink_port_attrs_pci_vf_set has 5 params and controller num], [
		#include <net/devlink.h>
	],[
		devlink_port_attrs_pci_vf_set(NULL, 1, 0, 0, 0);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_PORT_ATTRS_PCI_PF_SET_GET_2_PARAMS, [devlink.h devlink_port_attrs_pci_pf_set get 2 params], [
		#include <net/devlink.h>
	],[
		devlink_port_attrs_pci_pf_set(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_FMSG_BINARY_PAIR_NEST_START, [devlink.h has devlink_fmsg_binary_pair_nest_start is defined], [
		#include <net/devlink.h>
	],[
		devlink_fmsg_binary_pair_nest_start(NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_FLASH_UPDATE_STATUS_NOTIFY, [devlink_flash_update_status_notify], [
		#include <net/devlink.h>
	],[
		devlink_flash_update_status_notify(NULL, NULL, NULL, 0, 0);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_FLASH_UPDATE_END_NOTIFY, [devlink_flash_update_end_notify], [
		#include <net/devlink.h>
	],[
		devlink_flash_update_end_notify(NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_HEALTH_REPORTER_STATE_UPDATE, [devlink_health_reporter_state_update exist], [
		#include <net/devlink.h>
	],[
		devlink_health_reporter_state_update(NULL, 0);
		return 0;
	])

        MLNX_RDMA_TEST_CASE(HAVE_HEALTH_REPORTER_RECOVER_HAS_EXTACK, [devlink_health_reporter_ops.recover has extack], [
                #include <net/devlink.h>
		static int reporter_recover(struct devlink_health_reporter *reporter,
						     void *context,
						     struct netlink_ext_ack *extack)
		{
			return 0;
		}
        ],[
		struct devlink_health_reporter_ops mlx5_tx_reporter_ops = {
			.recover = reporter_recover
		};
        ])

        MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_PARAM_SET_FUNCTION_POINTER_HAS_EXTACK, [struct devlink_param set function pointer has extack parameter], [
                #include <net/devlink.h>
		static int param_set(struct devlink *devlink,
				     u32 id,
			             struct devlink_param_gset_ctx *ctx,
			             struct netlink_ext_ack *extack){ return 0;}
	],[
		struct devlink_param dp = {
			.set = param_set,
		};
        ])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_DRIVERINIT_VAL, [devlink_param_driverinit_value_get exist], [
		#include <net/devlink.h>
	],[
		devlink_param_driverinit_value_get(NULL, 0, NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_PARAM_GENERIC_ID_IO_EQ_SIZE, [devlink enum has DEVLINK_PARAM_GENERIC_ID_IO_EQ_SIZE], [
		#include <net/devlink.h>
	],[
		int i = DEVLINK_PARAM_GENERIC_ID_IO_EQ_SIZE;
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_PARAM_GENERIC_ID_ENABLE_ETH, [devlink enum has HAVE_DEVLINK_PARAM_GENERIC_ID_ENABLE_ETH], [
		#include <net/devlink.h>
	],[
		int i = DEVLINK_PARAM_GENERIC_ID_ENABLE_ETH;
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_PORT_NEW_ATTRS_STRUCT, [devlink struct devlink_port_new_attrs exist], [
		#include <net/devlink.h>
	],[
		struct devlink_port_new_attrs i;
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_PORT_ATRRS_SET_GET_7_PARAMS, [devlink_port_attrs_set has 7 parameters], [
		#include <net/devlink.h>
	],[
		devlink_port_attrs_set(NULL, 0, 0, 0, 0, NULL ,0);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_PORT_ATRRS_SET_GET_5_PARAMS, [devlink_port_attrs_set has 5 parameters], [
		#include <net/devlink.h>
	],[
		devlink_port_attrs_set(NULL, 0, 0, 0, 0);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_PORT_ATRRS_SET_GET_2_PARAMS, [devlink_port_attrs_set has 2 parameters], [
		#include <net/devlink.h>
	],[
		devlink_port_attrs_set(NULL, 0);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_PARAM_GENERIC_ID_ENABLE_ROCE, [struct devlink_param exist], [
		#include <net/devlink.h>
	],[
		int i = DEVLINK_PARAM_GENERIC_ID_ENABLE_ROCE;
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_PARAM_GENERIC_ID_ENABLE_REMOTE_DEV_RESET, [enum DEVLINK_PARAM_GENERIC_ID_ENABLE_REMOTE_DEV_RESET exist], [
		#include <net/devlink.h>
	],[
		int i = DEVLINK_PARAM_GENERIC_ID_ENABLE_REMOTE_DEV_RESET;
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_PORT_FN_STATE, [enum devlink_port_fn_state exist], [
                #include <uapi/linux/devlink.h>
        ],[
                enum devlink_port_fn_state fn_state;
                return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_PORT_FN_OPSTATE, [enum devlink_port_fn_opstate exist], [
                #include <uapi/linux/devlink.h>
        ],[
                enum devlink_port_fn_opstate fn_opstate;
                return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_PORT_FLAVOUR_VIRTUAL, [enum DEVLINK_PORT_FLAVOUR_VIRTUAL is defined], [
                #include <uapi/linux/devlink.h>
        ],[
                int i = DEVLINK_PORT_FLAVOUR_VIRTUAL;
                return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_PORT_FLAVOUR_PCI_SF, [enum DEVLINK_PORT_FLAVOUR_PCI_SF is defined], [
                #include <uapi/linux/devlink.h>
        ],[
                int i = DEVLINK_PORT_FLAVOUR_PCI_SF;
                return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_RELOAD_DISABLE, [devlink_reload_disable exist], [
		#include <net/devlink.h>
	],[
		devlink_reload_disable(NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_RELOAD_ENABLE, [devlink_reload_enable exist], [
		#include <net/devlink.h>
	],[
		devlink_reload_enable(NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_NET, [devlink_net exist], [
		#include <net/devlink.h>
	],[
		devlink_net(NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_HAS_RELOAD, [reload is defined], [
	        #include <net/devlink.h>

	        static int devlink_reload(struct devlink *devlink,
	                                struct netlink_ext_ack *extack)
	        {
	                return 0;
	        }

	],[
	        struct devlink_ops dlops = {
	                .reload = devlink_reload,
	        };

	        return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_HAS_RELOAD_UP_DOWN, [reload_up/down is defined], [
		#include <net/devlink.h>
	],[
		struct devlink_ops dlops = {
			.reload_up = NULL,
			.reload_down = NULL,
		};

		return 0;
	])

        MLNX_RDMA_TEST_CASE(HAVE_PORT_FUNCTION_HW_ADDR_GET_GET_4_PARAM, [port_function_hw_addr_get has 4 params], [
                #include <net/devlink.h>

		static int devlink_port_function_hw_addr_get(struct devlink_port *port, u8 *hw_addr,
							int *hw_addr_len,
							struct netlink_ext_ack *extack)
		{
		        return 0;
		}

        ],[
                struct devlink_ops dlops = {
                        .port_function_hw_addr_get = devlink_port_function_hw_addr_get,
		};

                return 0;
        ])

        MLNX_RDMA_TEST_CASE(HAVE_PORT_FUNCTION_STATE_GET_4_PARAM, [port_function_state_get has 4 params], [
                #include <net/devlink.h>

               static int mlx5_devlink_sf_port_fn_state_get(struct devlink_port *dl_port,
                                                            enum devlink_port_fn_state *state,
                                                            enum devlink_port_fn_opstate *opstate,
                                                            struct netlink_ext_ack *extack)
               {
                       return 0;
               }

        ],[
                struct devlink_ops dlops = {
                       .port_fn_state_get = mlx5_devlink_sf_port_fn_state_get,
               };

                return 0;
        ])

       MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_HAS_PORT_FUNCTION_STATE_GET, [port_function_state_get/set is defined], [
               #include <net/devlink.h>
       ],[
               struct devlink_ops dlops = {
                       .port_fn_state_get = NULL,
                       .port_fn_state_set = NULL,
               };

               return 0;
       ])

        MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_RELOAD_DOWN_HAS_3_PARAMS, [reload_down has 3 params], [
                #include <net/devlink.h>

		static int devlink_reload_down(struct devlink *devlink, bool netns_change,
                                    struct netlink_ext_ack *extack)
		{
		        return 0;
		}

        ],[
                struct devlink_ops dlops = {
                        .reload_down = devlink_reload_down,
		};

                return 0;
        ])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_RELOAD_DOWN_SUPPORT_RELOAD_ACTION, [reload_down has 5 params], [
                #include <net/devlink.h>

		static int devlink_reload_down(struct devlink *devlink, bool netns_change,
				enum devlink_reload_action action, enum devlink_reload_limit limit,
                		struct netlink_ext_ack *extack)
		{
		        return 0;
		}

        ],[
                struct devlink_ops dlops = {
                        .reload_down = devlink_reload_down,
		};

                return 0;
        ])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_PORT_OPS, [struct devlink_port_ops exists], [
		#include <net/devlink.h>
	],[
		struct devlink_port_ops dlops = {
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_HAS_INFO_GET, [info_get is defined], [
		#include <net/devlink.h>
	],[
		struct devlink_ops dlops = {
			.info_get = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_TRAP_SUPPORT, [devlink struct devlink_trap exists], [
		#include <net/devlink.h>
	],[
		struct devlink_trap t;
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_TRAP_DMAC_FILTER, [devlink has DEVLINK_TRAP_GENERIC_ID_DMAC_FILTER], [
		#include <net/devlink.h>
	],[
		int n = DEVLINK_TRAP_GENERIC_ID_DMAC_FILTER;
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_TRAP_ACTION_SET_4_ARGS, [devlink_ops.trap_action_set has 4 args], [
		#include <net/devlink.h>

		static int mlx5_devlink_trap_action_set(struct devlink *devlink,
							const struct devlink_trap *trap,
							enum devlink_trap_action action,
							struct netlink_ext_ack *extack)
		{
			return 0;
		}
	],[
		struct devlink_ops dlops = {
			.trap_action_set = mlx5_devlink_trap_action_set,
		};
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_TRAP_REPORT_5_ARGS, [devlink_trap_report has 5 args], [
		#include <net/devlink.h>
	],[
		devlink_trap_report(NULL, NULL, NULL, NULL, NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_TRAP_GROUP_GENERIC_2_ARGS, [devlink has DEVLINK_TRAP_GROUP_GENERIC with 2 args], [
		#include <net/devlink.h>
	],[
		static const struct devlink_trap_group mlx5_trap_groups_arr[[]] = {
			DEVLINK_TRAP_GROUP_GENERIC(L2_DROPS, 0),
		};
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_TRAP_GROUPS_REGISTER, [devlink has devlink_trap_groups_register], [
		#include <net/devlink.h>
	],[
		devlink_trap_groups_register(NULL, NULL, 0);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_PORT_HEALTH_REPORTER_CREATE, [devlink_health_reporter_create is defined], [
		#include <net/devlink.h>
	],[
		struct devlink_health_reporter *r;

		r = devlink_port_health_reporter_create(NULL, NULL, 0, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_PORT_HEALTH_REPORTER_DESTROY, [devlink_port_health_reporter_destroy is defined], [
		#include <net/devlink.h>
	],[
		devlink_port_health_reporter_destroy(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_HEALTH_REPORTER_CREATE_5_ARGS, [devlink_health_reporter_create has 5 args], [
		#include <net/devlink.h>
	],[
		struct devlink_health_reporter *r;

		r = devlink_health_reporter_create(NULL, NULL, 0, 0, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_HEALTH_REPORTER_CREATE_4_ARGS, [devlink_health_reporter_create has 4 args], [
		#include <net/devlink.h>
	],[
		struct devlink_health_reporter *r;

		r = devlink_health_reporter_create(NULL, NULL, 0, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_HEALTH_REPORT_BASE_SUPPORT, [structs devlink_health_reporter & devlink_fmsg exist], [
		#include <net/devlink.h>
	],[
		/* test for devlink_health_reporter and devlink_fmsg */
		struct devlink_health_reporter *r;
		struct devlink_fmsg *fmsg;
		int err;

		devlink_health_reporter_destroy(r);
		devlink_health_reporter_priv(r);

		err = devlink_health_report(r, NULL, NULL);

		devlink_fmsg_arr_pair_nest_start(fmsg, "name");
		devlink_fmsg_arr_pair_nest_end(fmsg);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_FMSG_BINARY_PUT, [devlink_fmsg_binary_put exists], [
		#include <net/devlink.h>
	],[
		struct devlink_fmsg *fmsg;
		int err;
		int value;

		err =  devlink_fmsg_binary_put(fmsg, &value, 2);
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_FMSG_BINARY_PAIR_PUT_ARG_U32_RETURN_INT, [devlink_fmsg_binary_pair_put exists], [
		#include <net/devlink.h>

		/* Only interested in function with arg u32 and not u16 */
		/* See upstream commit e2cde864a1d3e3626bfc8fa088fbc82b04ce66ed */
		int devlink_fmsg_binary_pair_put(struct devlink_fmsg *fmsg, const char *name, const void *value, u32 value_len);
	],[
		struct devlink_fmsg *fmsg;
		int err;
		int value;

		err =  devlink_fmsg_binary_pair_put(fmsg, "name", &value, 2);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_FMSG_BINARY_PAIR_PUT_ARG_U32_RETURN_VOID, [devlink_fmsg_binary_pair_put exists], [
		#include <net/devlink.h>

		/* Only interested in function with arg u32 and not u16 */
		/* See upstream commit e2cde864a1d3e3626bfc8fa088fbc82b04ce66ed */
		void devlink_fmsg_binary_pair_put(struct devlink_fmsg *fmsg, const char *name, const void *value, u32 value_len);
	],[
		struct devlink_fmsg *fmsg;
		int value;

		devlink_fmsg_binary_pair_put(fmsg, "name", &value, 2);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_ESWITCH_MODE_SET_EXTACK, [struct devlink_ops.eswitch_mode_set has extack], [
		#include <net/devlink.h>
		int mlx5_devlink_eswitch_mode_set(struct devlink *devlink, u16 mode,
		                                struct netlink_ext_ack *extack);
		int mlx5_devlink_eswitch_mode_set(struct devlink *devlink, u16 mode,
		                                struct netlink_ext_ack *extack) {
			return 0;
		}
	],[
		static const struct devlink_ops dlops = {
			.eswitch_mode_set = mlx5_devlink_eswitch_mode_set,
		};
		dlops.eswitch_mode_set(NULL, 0, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_SWITCHDEV_INACTIVE_MODE, [DEVLINK_ESWITCH_MODE_SWITCHDEV_INACTIVE exists], [
		#include <uapi/linux/devlink.h>
	],[
		enum devlink_eswitch_mode mode;
		mode = DEVLINK_ESWITCH_MODE_SWITCHDEV_INACTIVE;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_HAS_PORT_FN_ROCE_MIG, [port_function_roce/mig_get/set is defined], [
		#include <net/devlink.h>
	],[
		struct devlink_ops dlops = {
			.port_fn_migratable_get = NULL,
			.port_fn_migratable_set = NULL,
			.port_fn_roce_get = NULL,
			.port_fn_roce_set = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_HAS_PORT_FUNCTION_HW_ADDR_GET, [port_function_hw_addr_get/set is defined], [
		#include <net/devlink.h>
	],[
		struct devlink_ops dlops = {
			.port_function_hw_addr_get = NULL,
			.port_function_hw_addr_set = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_HAS_RATE_FUNCTIONS, [rate functions are defined], [
		#include <net/devlink.h>
	],[
		struct devlink_ops dlops = {
			.rate_leaf_tx_share_set = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_HAS_RATE_TC_BW_SET, [rate tc_bw_set functions are defined], [
		#include <net/devlink.h>
	],[
		struct devlink_ops dlops = {
			.rate_leaf_tc_bw_set = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_HAS_ESWITCH_ENCAP_MODE_SET_GET_WITH_ENUM, [eswitch_encap_mode_set/get is defined with enum], [
		#include <net/devlink.h>
		#include <uapi/linux/devlink.h>

		int local_eswitch_encap_mode_get(struct devlink *devlink,
					      enum devlink_eswitch_encap_mode *p_encap_mode);
		int local_eswitch_encap_mode_get(struct devlink *devlink,
					      enum devlink_eswitch_encap_mode *p_encap_mode) {
			return 0;
		}
		int local_eswitch_encap_mode_set(struct devlink *devlink,
					      enum devlink_eswitch_encap_mode encap_mode,
					      struct netlink_ext_ack *extack);
		int local_eswitch_encap_mode_set(struct devlink *devlink,
					      enum devlink_eswitch_encap_mode encap_mode,
					      struct netlink_ext_ack *extack) {
			return 0;
		}
	],[
		struct devlink_ops dlops = {
			.eswitch_encap_mode_set = local_eswitch_encap_mode_set,
			.eswitch_encap_mode_get = local_eswitch_encap_mode_get,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_HAS_FLASH_UPDATE, [flash_update is defined], [
		#include <net/devlink.h>
	],[
		struct devlink_ops dlops = {
			.flash_update = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLASH_UPDATE_GET_3_PARAMS, [struct devlink_ops flash_update get 3 params], [
		#include <net/devlink.h>
		#include <linux/netlink.h>

		static int flash_update_func(struct devlink *devlink,
			    struct devlink_flash_update_params *params,
			    struct netlink_ext_ack *extack)
		{
			return 0;
		}
	],[
		struct devlink_ops dlops = {
			.flash_update = flash_update_func,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_PORT_ATTRS_PCI_PF_SET_4_PARAMS, [devlink_port_attrs_pci_pf_set has 4 params], [
		#include <net/devlink.h>
	],[
		devlink_port_attrs_pci_pf_set(NULL, NULL, 0, 0);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_PORT_ATTRS_PCI_PF_SET_CONTROLLER_NUM, [devlink_port_attrs_pci_pf_set has 4 params and controller num], [
		#include <net/devlink.h>
	],[
		devlink_port_attrs_pci_pf_set(NULL, 1, 0, 0);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_PORT_ATTRS_PCI_PF_SET_2_PARAMS, [devlink_port_attrs_pci_pf_set has 2 params], [
		#include <net/devlink.h>
	],[
		devlink_port_attrs_pci_pf_set(NULL, 0);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_FLASH_UPDATE_PARAMS_HAS_STRUCT_FW, [devlink_flash_update_params has struct firmware fw], [
		#include <net/devlink.h>
	],[
		struct devlink_flash_update_params *x;
		x->fw = NULL;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NETIF_CARRIER_EVENT, [netif_carrier_event exists], [
		#include <linux/netdevice.h>
	],[
		netif_carrier_event(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NETIF_DEVICE_PRESENT_GET_CONST, [netif_device_present get const], [
		#include <linux/netdevice.h>
	],[
		const struct net_device *dev;
		netif_device_present(dev);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_PORT_HAS_SWITCH_PORT, [struct devlink_port has attrs.switch_port], [
		#include <net/devlink.h>
	],[
		struct devlink_port *port;

		port->attrs.switch_port = true;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_PORT_HAS_SWITCH_ID, [struct devlink_port has attrs.switch_id], [
		#include <net/devlink.h>
	],[
		struct devlink_port *port;

		port->attrs.switch_id.id_len = 0;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NET_DEVICE_HAS_DEVLINK_PORT, [struct net_device has devlink_port], [
		#include <linux/netdevice.h>
	],[
		struct net_device *dev;

		dev->devlink_port = NULL;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NET_DEVICE_LOWER_LEVEL, [struct net_device has lower_level], [
		#include <linux/netdevice.h>
	],[
		struct net_device dev;

		dev.lower_level = 1;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NETDEV_LAG_HASH_VLAN_SRCMAC, [netdev_lag_hash has NETDEV_LAG_HASH_VLAN_SRCMAC], [
		#include <linux/netdevice.h>
	],[
		int x = NETDEV_LAG_HASH_VLAN_SRCMAC;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ETHTOOL_LINK_KSETTINGS_HAS_LANES, [ethtool_link_ksettings has lanes], [
		#include <linux/ethtool.h>
	],[
                struct ethtool_link_ksettings x = {
			.lanes = 0,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_KERNEL_RINGPARAM_TCP_DATA_SPLIT, [ethtool.h kernel_ethtool_ringparam has tcp_data_split member], [
		#include <linux/ethtool.h>
	],[
                struct kernel_ethtool_ringparam x = {
			.tcp_data_split = 0,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_STRUCT_KERNEL_ETHTOOL_RINGPARAM, [ethtool.h has struct kernel_ethtool_ringparam], [
		#include <linux/ethtool.h>
	],[
                struct kernel_ethtool_ringparam x;
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_STRUCT_KERNEL_ETHTOOL_TS_INFO, [ethtool.h has struct kernel_ethtool_ts_info], [
		#include <linux/ethtool.h>
	],[
                struct kernel_ethtool_ts_info x;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ETHTOOL_PUTS, [ethtool.h has ethtool_puts], [
		#include <linux/ethtool.h>
	],[
                ethtool_puts(NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_CAP_RSS_SYM_XOR_SUPPORTED, [cap_rss_sym_xor_supported is defined], [
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.cap_rss_sym_xor_supported = 0,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ETHTOOL_OPS_HAS_PER_CTX_KEY, [rxfh_per_ctx_key is defined], [
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.rxfh_per_ctx_key = 0,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ETHTOOL_OPS_HAS_PER_CTX_FIELDS, [rxfh_per_ctx_fields is defined], [
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.rxfh_per_ctx_fields = 0,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SUPPORTED_COALESCE_PARAM, [supported_coalesce_params is defined], [
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.supported_coalesce_params = 0,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_GET_MODULE_EEPROM_BY_PAGE, [ethtool_ops has get_module_eeprom_by_page], [
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.get_module_eeprom_by_page = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TLS_IS_SKB_TX_DEVICE_OFFLOADED, [net/tls.h has tls_is_skb_tx_device_offloaded], [
		#include <net/tls.h>
	],[
		tls_is_skb_tx_device_offloaded(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TLS_OFFLOAD_RESYNC_ASYNC_STRUCT, [net/tls.h has struct tls_offload_resync_async is defined], [
		#include <net/tls.h>
	],[
		struct tls_offload_resync_async	x;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_KTLS_STRUCTS, [ktls related structs exists], [
		#include <linux/netdevice.h>
		#include <net/tls.h>
	],[
		struct tlsdev_ops dev;
		struct tls_offload_context_tx tx_ctx;
		struct tls12_crypto_info_aes_gcm_128 crypto_info;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TLSDEV_OPS_HAS_TLS_DEV_RESYNC, [struct tlsdev_ops has tls_dev_resync], [
		#include <net/tls.h>
	],[
		struct tlsdev_ops dev;

		dev.tls_dev_resync = NULL;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SKB_FRAG_FILL_PAGE_DESC, [linux/skbuff.h skb_frag_fill_page_desc is defined], [
		#include <linux/skbuff.h>
	],[
		skb_frag_fill_page_desc(NULL, NULL, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SKB_COPY_AND_CRC32C_DATAGRAM_ITER, [skb_copy_and_crc32c_datagram_iter exist], [
		#include <linux/skbuff.h>
	],[
		skb_copy_and_crc32c_datagram_iter(NULL, 0, NULL, 0, NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NAPI_BUILD_SKB, [linux/skbuff.h napi_build_skb is defined], [
		#include <linux/skbuff.h>
	],[
		napi_build_skb(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SKB_IS_GSO_TCP, [linux/skbuff.h skb_is_gso_tcp is defined], [
		#include <linux/skbuff.h>
	],[
		skb_is_gso_tcp(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SKB_FRAG_OFF_ADD, [linux/skbuff.h skb_frag_off_add is defined], [
		#include <linux/skbuff.h>
	],[
		skb_frag_off_add(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SKB_FRAG_OFF_SET, [linux/skbuff.h skb_frag_off_set is defined], [
		#include <linux/skbuff.h>
	],[
		skb_frag_off_set(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NET_NETDEV_LOCK_H, [net/netdev_lock.h header exists], [
		#include <net/netdev_lock.h>
	],[
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NETDEVICE_NETDEV_LOCK, [netdev_lock exists], [
		#include <linux/netdevice.h>
	],[
		netdev_lock(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SET_DEFAULT_D_OP, [set_default_d_op function exists], [
		#include <linux/dcache.h>
	],[
		struct super_block *sb = NULL;
		const struct dentry_operations *ops = NULL;
		set_default_d_op(sb, ops);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_STRUCT_FILE_KATTR, [struct file_kattr exists], [
		#include <linux/fileattr.h>
	],[
		struct file_kattr fa;
		fa.flags = 0;
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_LINUX_PFN_T_H, [linux/pfn_t.h header exists], [
		#include <linux/pfn_t.h>
	],[
		pfn_t pfn;
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_GROUP_CPUS_EVENLY_NUMMASKS, [group_cpus_evenly takes nummasks parameter], [
		#include <linux/group_cpus.h>
	],[
		unsigned int nummasks;
		struct cpumask *masks = group_cpus_evenly(1, &nummasks);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ADDRESS_SPACE_WRITE_BEGIN_KIOCB, [write_begin takes const struct kiocb *], [
		#include <linux/fs.h>
		#include <linux/pagemap.h>

		static int test_write_begin(const struct kiocb *iocb,
					    struct address_space *mapping,
					    loff_t pos, unsigned len,
					    struct folio **foliop, void **fsdata);
		static int test_write_begin(const struct kiocb *iocb,
					    struct address_space *mapping,
					    loff_t pos, unsigned len,
					    struct folio **foliop, void **fsdata)
		{
			return 0;
		}
	],[
		struct address_space_operations aops = {
			.write_begin = test_write_begin,
		};
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NET_DEVICE_LOCK_FIELD, [net_device has lock field], [
		#include <linux/netdevice.h>
		#include <linux/mutex.h>
	],[
		struct net_device dev;
		dev.lock = (struct mutex){};
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NR_WRITEBACK_TEMP, [NR_WRITEBACK_TEMP enum exists], [
		#include <linux/mmzone.h>
	],[
		enum node_stat_item item = NR_WRITEBACK_TEMP;
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_WRITEBACK_CONTROL_FOR_RECLAIM, [writeback_control has for_reclaim field], [
		#include <linux/writeback.h>
	],[
		struct writeback_control wbc;
		wbc.for_reclaim = 0;
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_UDP_TUNNEL_NIC_INFO_MAY_SLEEP, [UDP_TUNNEL_NIC_INFO_MAY_SLEEP flag exists], [
		#include <net/udp_tunnel.h>
	],[
		enum udp_tunnel_nic_info_flags flags = UDP_TUNNEL_NIC_INFO_MAY_SLEEP;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ETHTOOL_OPS_CAP_RSS_CTX_SUPPORTED, [ethtool_ops has cap_rss_ctx_supported field], [
		#include <linux/ethtool.h>
	],[
		struct ethtool_ops ops;
		ops.cap_rss_ctx_supported = true;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ETHTOOL_GET_RXFH_FIELDS, [ethtool_ops has get_rxfh_fields callback], [
		#include <linux/ethtool.h>
	],[
		struct ethtool_ops ops = {
			.get_rxfh_fields = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_CYCLECOUNTER_READ_NON_CONST, [cyclecounter read callback takes non-const parameter], [
		#include <linux/timecounter.h>

		static u64 test_read(struct cyclecounter *cc);
		static u64 test_read(struct cyclecounter *cc)
		{
			return 0;
		}
	],[
		struct cyclecounter cc = {
			.read = test_read,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_INTEGRITY_METADATA_SIZE, [blk_integrity has metadata_size field], [
		#include <linux/blkdev.h>
	],[
		struct blk_integrity bi;
		bi.metadata_size = 0;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NETIF_GET_PORT_PARENT_ID_FUNC, [netif_get_port_parent_id function exists], [
		#include <linux/netdevice.h>
	],[
		struct net_device *dev = NULL;
		struct netdev_phys_item_id ppid;

		netif_get_port_parent_id(dev, &ppid, false);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TIMER_DELETE, [timer_delete exists], [
		#include <linux/netdevice.h>
	],[
		timer_delete(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NAPI_RESCHEDULE, [napi_reschedule exists], [
		#include <linux/netdevice.h>
	],[
		int ret;

		ret = napi_reschedule(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NETDEV_NETNS_LOCAL, [struct net_device has netns_local as member], [
		#include <linux/netdevice.h>
	],[
		struct net_device netdev = {
			.netns_local = 0,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NETDEV_NETNS_IMMUTABLE, [struct net_device has netns_local as member], [
		#include <linux/netdevice.h>
	],[
		struct net_device netdev = {
			.netns_immutable = 0,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NETDEV_DEVLINK_PORT, [struct net_device has devlink_port as member], [
		#include <linux/netdevice.h>
	],[
		struct net_device netdev = {
			.devlink_port = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NDO_PORT_DEL_IN_DEVLINK_PORT, [struct ndevlink_port_ops has devlink_port as member], [
		#include <net/devlink.h>
	],[
		static const struct devlink_port_ops ops= {
			.port_del = NULL,
		};

		return 0;
	])


	MLNX_RDMA_TEST_CASE(HAVE_NDO_XSK_WAKEUP, [ndo_xsk_wakeup is defined], [
		#include <linux/netdevice.h>
	],[
		struct net_device_ops netdev_ops = {
			.ndo_xsk_wakeup = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ENUM_TC_HTB_COMMAND, [enum tc_htb_command is defined], [
		#include <net/pkt_cls.h>
	],[
		enum tc_htb_command x;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TC_HTB_OPT_PRIO, [tc_htb_qopt_offload has prio], [
		#include <net/pkt_cls.h>
	],[
		struct tc_htb_qopt_offload x;

		x.prio = 0;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TC_HTB_OPT_QUANTUM, [tc_htb_qopt_offload has quantum], [
		#include <net/pkt_cls.h>
	],[
		struct tc_htb_qopt_offload x;

		x.quantum = 0;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TC_FLOWER_OFFLOAD, [struct tc_cls_flower_offload is defined], [
		#include <net/pkt_cls.h>
	],[
		struct tc_cls_flower_offload x;
		x = x;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TC_BLOCK_OFFLOAD, [struct tc_block_offload is defined], [
		#include <net/pkt_cls.h>
	],[
		struct tc_block_offload x;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_BLOCK_OFFLOAD, [struct flow_block_offload exists], [
		#include <net/pkt_cls.h>
	],[
		struct flow_block_offload x;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_UNLOCKED_DRIVER_CB, [struct flow_block_offload has unlocked_driver_cb], [
		#include <net/pkt_cls.h>
	],[
		struct flow_block_offload x;
		x.unlocked_driver_cb = true;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NL_ASSERT_CTX_FITS, [NL_ASSERT_CTX_FITS exists], [
		#include <linux/netlink.h>
	],[

		NL_ASSERT_CTX_FITS(int);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NETMEM_DMA_UNMAP_ADDR_SET, [HAVE_NETMEM_DMA_UNMAP_ADDR_SET exists], [
		#include <net/netmem.h>

	],[
		#ifdef netmem_dma_unmap_addr_set
			return 0;
		#else
			#return 1
		#endif
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NL_SET_ERR_MSG_WEAK_MOD, [NL_SET_ERR_MSG_WEAK_MOD exists], [
		#include <linux/netlink.h>

	],[
		#ifdef NL_SET_ERR_MSG_WEAK_MOD
			return 0;
		#else
			#return 1
		#endif
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NL_SET_ERR_MSG_FMT_MOD, [include/linux/netlink.h provides NL_SET_ERR_MSG_FMT_MOD], [
		#include <linux/netlink.h>
	],[
		struct netlink_ext_ack extack = {};

		NL_SET_ERR_MSG_FMT_MOD(&extack, "test");
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TC_BLOCK_OFFLOAD_EXTACK, [struct tc_block_offload has extack], [
		#include <net/pkt_cls.h>
	],[
		struct tc_block_offload x;
		x.extack = NULL;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TC_MQPRIO_EXTACK, [struct tc_mqprio_qopt_offload has extack], [
		#include <net/pkt_sched.h>
	],[
		struct tc_mqprio_qopt_offload x;
		x.extack = NULL;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_GETTIMEX64, [gettimex64 is defined], [
		#include <linux/ptp_clock_kernel.h>
	],[
		struct ptp_clock_info info = {
			.gettimex64 = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PTP_CLOCK_INFO_NDO_GETMAXPHASE, [struct ptp_clock_info has getmaxphase], [
		#include <linux/ptp_clock_kernel.h>
	],[
		struct ptp_clock_info info = {
			.getmaxphase = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PTP_CLOCK_INFO_NDO_ADJFREQ, [adjfreq is defined], [
		#include <linux/ptp_clock_kernel.h>
	],[
		struct ptp_clock_info info = {
			.adjfreq = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PTP_CLOCK_INFO_ADJPHASE, [adjphase is defined], [
		#include <linux/ptp_clock_kernel.h>
	],[
		struct ptp_clock_info info = {
			.adjphase = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ADJUST_BY_SCALED_PPM, [adjfine is defined], [
		#include <linux/ptp_clock_kernel.h>
	],[
		adjust_by_scaled_ppm(0,0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PCI_VPD_FIND_TAG_GET_4_PARAM, [pci_dev has pci_vpd_find_tag get 4 params], [
		#include <linux/pci.h>
	],[
		pci_vpd_find_tag(NULL , 0, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PCI_VPD_ALLOC, [pci_dev has pci_vpd_alloc], [
		#include <linux/pci.h>
	],[
		pci_vpd_alloc(NULL ,NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PCI_DEV_LINK_ACTIVE_REPORTING, [pci_dev has link_active_reporting], [
		#include <linux/pci.h>
	],[
		struct pci_dev *bridge;
		bridge->link_active_reporting = 0;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PCI_IOV_VF_ID, [pci_iov_vf_id is defined], [
		#include <linux/pci.h>
	],[
		pci_iov_vf_id(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PCI_IOV_GET_PF_DRVDATA, [pci_iov_get_pf_drvdata is defined], [
		#include <linux/pci.h>
	],[
		pci_iov_get_pf_drvdata(NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_WANT_INIT_ON_ALLOC, [want_init_on_alloc is defined], [
		#include <linux/mm.h>
	],[
		bool x = want_init_on_alloc(__GFP_ZERO);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PAGE_DMA_ADDR_ARRAY, [struct page has dma_addr array member], [
		#include <linux/mm_types.h>
	],[
		struct page page;

		page.dma_addr[[0]] = 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SKB_FRAG_OFF, [skb_frag_off is defined], [
		#include <linux/skbuff.h>
	],[
		skb_frag_off(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEV_PAGE_IS_REUSABLE, [dev_page_is_reusable is defined], [
		#include <linux/skbuff.h>
	],[
		dev_page_is_reusable(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TC_SKB_EXT_ALLOC, [tc_skb_ext_alloc is defined], [
		#include <linux/skbuff.h>
		#include <net/pkt_cls.h>
	],[
		struct sk_buff skb;

		tc_skb_ext_alloc(&skb);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEV_CHANGE_FLAGS_HAS_3_PARAMS, [dev_change_flags has 3 parameters], [
		#include <linux/netdevice.h>
	],[
		dev_change_flags(NULL, 0, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_USER_ACCESS_BEGIN_2_PARAMS, [user_access_begin has 2 parameters], [
		#include <linux/uaccess.h>
	],[
		size_t size = 0;
		const void __user *from = NULL;

		if (!user_access_begin(from, size))
			return 0;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_USER_ACCESS_BEGIN_3_PARAMS, [user_access_begin has 3 parameters], [
		#include <linux/uaccess.h>
	],[
		size_t size = 0;
		const void __user *from = NULL;

		if (!user_access_begin(VERIFY_READ, from, size))
			return 0;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ACCESS_OK_HAS_3_PARAMS, [access_ok has 3 parameters], [
		#include <linux/uaccess.h>
	],[
		access_ok(0, NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_CHECK_ZEROED_USER, [access_ok has check_zeroed_user], [
		#include <linux/uaccess.h>
	],[
		int ret;

		ret = check_zeroed_user(NULL,0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PUT_USER_PAGES_DIRTY_LOCK_3_PARAMS, [put_user_pages_dirty_lock has 3 parameters], [
		#include <linux/mm.h>
	],[
		put_user_pages_dirty_lock(NULL, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PUT_USER_PAGES_DIRTY_LOCK_2_PARAMS, [put_user_pages_dirty_lock has 2 parameters], [
		#include <linux/mm.h>
	],[
		put_user_pages_dirty_lock(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_DISSECTOR_MPLS_LSE, [flow_dissector.h has struct flow_dissector_mpls_lse], [
		#include <net/flow_dissector.h>
	],[
		struct flow_dissector_mpls_lse ls;
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_DISSECTOR_USED_KEYS_ULL, [struct flow_dissector has unsigned long long used_keys], [
		#include <net/flow_dissector.h>
	],[
		struct flow_dissector *fd;
		_Static_assert(__builtin_types_compatible_p(typeof(fd->used_keys), unsigned long long),
               "");
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SWITCHDEV_ATTR_ID_BRIDGE_VLAN_PROTOCOL, [enum switchdev_attr_id has SWITCHDEV_ATTR_ID_BRIDGE_VLAN_PROTOCOL], [
		#include <net/switchdev.h>
	],[
		enum switchdev_attr_id x = SWITCHDEV_ATTR_ID_BRIDGE_VLAN_PROTOCOL;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SWITCHDEV_OPS, [HAVE_SWITCHDEV_OPS is defined], [
		#include <net/switchdev.h>
		#include <linux/netdevice.h>

		/* Declare here to avoid dandling pointer error */
		static struct switchdev_ops x;
	],[
		struct net_device *ndev;

		ndev->switchdev_ops = &x;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_STRUCT_SWITCHDEV_OBJ_PORT_VLAN_VID, [struct switchdev_obj_port_vlan has vid], [
		#include <net/switchdev.h>
	],[
		struct switchdev_obj_port_vlan x;
		x.vid = 0;

		return 0;
	])
	MLNX_RDMA_TEST_CASE(HAVE_STRUCT_SWITCHDEV_BRPORT_FLAGS, [struct switchdev_brport_flags exist], [
		#include <net/switchdev.h>
	],[
		struct switchdev_brport_flags x;
		x.mask = 0;

		return 0;
	])


	MLNX_RDMA_TEST_CASE(HAVE_SWITCHDEV_PORT_SAME_PARENT_ID, [switchdev_port_same_parent_id is defined], [
		#include <net/switchdev.h>
	],[
		switchdev_port_same_parent_id(NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SK_BUFF_XMIT_MORE, [xmit_more is defined], [
		#include <linux/skbuff.h>
	],[
		struct sk_buff *skb;
		skb->xmit_more = 0;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XFRM_DEV_OFFLOAD_FLAG_ACQ, [xfrm_dev_offload has flags], [
		#include <net/xfrm.h>
	],[
		struct xfrm_dev_offload x = {
                        .flags = XFRM_DEV_OFFLOAD_FLAG_ACQ,
                };

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XFRM_DEV_REAL_DEV, [xfrm_dev_offload has real_dev as member], [
		#include <net/xfrm.h>
	],[
		struct xfrm_dev_offload x = {
                        .real_dev = NULL,
                };

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XFRM_STATE_DIR, [xfrm_dev_offload has state as member], [
		#include <net/xfrm.h>
	],[
		struct xfrm_state_offload x = {
                        .dir = 0,
                };

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XFRM_DEV_DIR, [xfrm_dev_offload has dir as member], [
		#include <net/xfrm.h>
	],[
		struct xfrm_dev_offload x = {
                        .dir = 0,
                };

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XFRM_DEV_TYPE, [xfrm_dev_offload has type as member], [
		#include <net/xfrm.h>
	],[
		struct xfrm_dev_offload x = {
                        .type = 0,
                };

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XFRM_STATE_REAL_DEV, [xfrm_state_offload has real_dev as member], [
		#include <net/xfrm.h>
	],[
		struct xfrm_state_offload x = {
                        .real_dev = NULL,
                };

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SECPATH_SET_RETURN_POINTER, [if secpath_set returns struct sec_path *], [
		#include <net/xfrm.h>
	],[
		struct sec_path *temp = secpath_set(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ETH_GET_HEADLEN_3_PARAMS, [eth_get_headlen is defined with 3 params], [
		#include <linux/etherdevice.h>
	],[
		eth_get_headlen(NULL, NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ETH_GET_HEADLEN_2_PARAMS, [eth_get_headlen is defined with 2 params], [
		#include <linux/etherdevice.h>
	],[
		eth_get_headlen(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_VLAN_GET_ENCAP_LEVEL, [vlan_get_encap_level is defined], [
		#include <linux/if_vlan.h>
	],[
		vlan_get_encap_level(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_VLAN_ETHHDR_HAS_ADDRS, [struct vlan_ethhdr has addrs member], [
		#include <linux/if_vlan.h>
	],[
		struct vlan_ethhdr vhdr = {
			.addrs = {(0)},
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NDO_SELECT_QUEUE_HAS_3_PARMS_NO_FALLBACK, [ndo_select_queue has 3 params with no fallback], [
		#include <linux/netdevice.h>

		static u16 select_queue(struct net_device *dev, struct sk_buff *skb,
				        struct net_device *sb_dev);
		static u16 select_queue(struct net_device *dev, struct sk_buff *skb,
				        struct net_device *sb_dev)
		{
			return 0;
		}
	],[
		struct net_device_ops ndops = {
			.ndo_select_queue = select_queue,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SELECT_QUEUE_NET_DEVICE, [ndo_select_queue has a second net_device parameter], [
		#include <linux/netdevice.h>

		static u16 select_queue(struct net_device *dev, struct sk_buff *skb,
		                        struct net_device *sb_dev,
		                        select_queue_fallback_t fallback);
		static u16 select_queue(struct net_device *dev, struct sk_buff *skb,
		                        struct net_device *sb_dev,
		                        select_queue_fallback_t fallback)
		{
			return 0;
		}
	],[
		struct net_device_ops ndops = {
			.ndo_select_queue = select_queue,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_CLEANUP_H, [include/linux/cleanup.h exists], [
		#include <linux/cleanup.h>
	],[
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_CONTAINER_OF_H, [include/linux/container_of.h exists], [
		#include <linux/container_of.h>
	],[
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PANIC_H, [include/linux/panic.h exists], [
		#include <linux/panic.h>
	],[
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BITS_H, [include/linux/bits.h exists], [
		#include <linux/bits.h>
	],[
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_ALLOC_NS, [include/net/devlink.h devlink_alloc_ns defined], [
		#include <net/devlink.h>
	],[
		devlink_alloc_ns(NULL, 0, NULL, NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_DISSECTOR_KEY_VLAN_ETH_TYPE, [struct flow_dissector_key_vlan has vlan_eth_type], [
		#include <net/flow_dissector.h>
	],[
		struct flow_dissector_key_vlan vlan;

		vlan.vlan_eth_type = 0;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_MATCH_META_L2_MISS, [struct flow_dissector_key_meta has l2_miss], [
		#include <net/flow_dissector.h>
	],[
		struct flow_dissector_key_meta key;

		key.l2_miss = 0;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_ACTION_CONTINUE, [FLOW_ACTION_CONTINUE exists], [
		#include <net/flow_offload.h>
	],[
		enum flow_action_id action = FLOW_ACTION_CONTINUE;
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_ACTION_JUMP_AND_PIPE, [FLOW_ACTION_JUMP and PIPE exists], [
		#include <net/flow_offload.h>
	],[
		enum flow_action_id action = FLOW_ACTION_JUMP;
		enum flow_action_id action2 = FLOW_ACTION_PIPE;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_ACTION_PRIORITY, [FLOW_ACTION_PRIORITY exists], [
		#include <net/flow_offload.h>
	],[
		enum flow_action_id action = FLOW_ACTION_PRIORITY;
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_ACTION_VLAN_PUSH_ETH, [FLOW_ACTION_VLAN_PUSH_ETH exists], [
		#include <net/flow_offload.h>
	],[
		enum flow_action_id action = FLOW_ACTION_VLAN_PUSH_ETH;
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_OFFLOAD_ACTION, [HAVE_FLOW_OFFLOAD_ACTION exists], [
		#include <net/flow_offload.h>
	],[
		struct flow_offload_action act = {};
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_OFFLOAD_ACTION_LAST_ENTRY, [function flow_action_is_last_entry exists], [
		#include <net/flow_offload.h>
	],[
		flow_action_is_last_entry(NULL, NULL);
		return 0;
	])
	MLNX_RDMA_TEST_CASE(HAVE_FLOW_RULE_MATCH_CT, [flow_rule_match_ct exists], [
		#include <net/flow_offload.h>
	],[
		flow_rule_match_ct(NULL, NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_OFFLOAD_HAS_ONE_ACTION, [flow_offload_has_one_action exists], [
		#include <net/flow_offload.h>
	],[
		struct flow_action action;

		flow_offload_has_one_action(&action);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TC_SETUP_CB_ADD, [tc_setup_cb_add is defined], [
		#include <net/pkt_cls.h>
	],[
		tc_setup_cb_add(NULL, NULL, 0, NULL ,0 ,NULL, NULL ,0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TC_SETUP_FLOW_ACTION_FUNC, [tc_setup_flow_action is defined], [
		#include <net/pkt_cls.h>
	],[
		tc_setup_flow_action(NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TC_SETUP_OFFLOAD_ACTION_FUNC, [tc_setup_offload_action is defined], [
		#include <net/pkt_cls.h>
	],[
		tc_setup_offload_action(NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TC_SETUP_OFFLOAD_ACTION_FUNC_HAS_3_PARAM, [tc_setup_offload_action is defined and get 3 param], [
		#include <net/pkt_cls.h>
	],[
		tc_setup_offload_action(NULL, NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TC_SETUP_FLOW_ACTION_WITH_RTNL_HELD, [tc_setup_flow_action has rtnl_held], [
		#include <net/pkt_cls.h>
	],[
		tc_setup_flow_action(NULL, NULL, false);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE___TC_INDR_BLOCK_CB_REGISTER, [__tc_indr_block_cb_register is defined], [
		#include <net/pkt_cls.h>
	],[
		__tc_indr_block_cb_register(NULL, NULL, NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TC_CLSMATCHALL_STATS, [TC_CLSMATCHALL_STATS is defined], [
		#include <net/pkt_cls.h>
	],[
		enum tc_matchall_command x = TC_CLSMATCHALL_STATS;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE___FLOW_INDR_BLOCK_CB_REGISTER, [__flow_indr_block_cb_register is defined], [
		#include <net/flow_offload.h>
	],[
		__flow_indr_block_cb_register(NULL, NULL, NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_CLS_OFFLOAD_FLOW_RULE, [flow_cls_offload_flow_rule is defined], [
		#include <net/flow_offload.h>
	],[
		flow_cls_offload_flow_rule(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_BLOCK_CB_SETUP_SIMPLE, [flow_block_cb_setup_simple is defined], [
		#include <net/flow_offload.h>
	],[
		flow_block_cb_setup_simple(NULL, NULL, NULL, NULL, NULL, false);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_BLOCK_CB_ALLOC, [flow_block_cb_alloc is defined], [
		#include <net/flow_offload.h>
	],[
		flow_block_cb_alloc(NULL, NULL, NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_SETUP_CB_T, [flow_setup_cb_t is defined], [
		#include <net/flow_offload.h>
	],[
		flow_setup_cb_t *cb = NULL;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_IPV6_STUBS_H, [net/ipv6_stubs.h exists], [
		#include <net/ipv6_stubs.h>
	],[
		return 0;
	])

       MLNX_RDMA_TEST_CASE(HAVE_RPS_H, [net/rps.h exists], [
              #include <net/rps.h>
       ],[
              return 0;
       ])

	MLNX_RDMA_TEST_CASE(HAVE_NDO_ETH_IOCTL, [net_device_ops has ndo_eth_ioctl is defined], [
		#include <linux/netdevice.h>
	],[
		struct net_device_ops netdev_ops = {
			.ndo_eth_ioctl = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NDO_GET_PORT_PARENT_ID, [HAVE_NDO_GET_PORT_PARENT_ID is defined], [
		#include <linux/netdevice.h>

		int get_port_parent_id(struct net_device *dev,
				       struct netdev_phys_item_id *ppid);
		int get_port_parent_id(struct net_device *dev,
				       struct netdev_phys_item_id *ppid)
		{
			return 0;
		}
	],[
		struct net_device_ops netdev_ops;

		netdev_ops.ndo_get_port_parent_id = get_port_parent_id;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NETDEV_NESTED_PRIV_STRUCT, [netdevice.h has struct netdev_nested_priv], [
		#include <linux/netdevice.h>
	],[
		struct netdev_nested_priv x;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEV_GET_PORT_PARENT_ID_FUNC, [function dev_get_port_parent_id exists], [
        #include <linux/netdevice.h>
        ],[
                dev_get_port_parent_id(NULL, NULL, 0);
                return 0;
        ])

	MLNX_RDMA_TEST_CASE(HAVE_DEV_ADDR_MOD, [function dev_addr_mod exists], [
        #include <linux/netdevice.h>
        ],[
                dev_addr_mod(NULL, 0, NULL, 0);
                return 0;
        ])

	MLNX_RDMA_TEST_CASE(HAVE_NETDEV_GET_XMIT_SLAVE, [function netdev_get_xmit_slave exists], [
        #include <linux/netdevice.h>
        ],[
                netdev_get_xmit_slave(NULL, NULL, 0);
                return 0;
        ])

        MLNX_RDMA_TEST_CASE(HAVE_NET_LAG_H, [net/lag.h exists], [
                #include <net/lag.h>
        ],[
                return 0;
        ])

	MLNX_RDMA_TEST_CASE(HAVE_NET_LAG_PORT_DEV_TXABLE, [net/lag.h exists], [
                #include <net/lag.h>
        ],[
		net_lag_port_dev_txable(NULL);

                return 0;
        ])

	MLNX_RDMA_TEST_CASE(HAVE_GET_RINGPARAM_GET_4_PARAMS, [ndo_get_ringparam get 4 parameters], [
		#include <linux/ethtool.h>

		static void ipoib_get_ringparam(struct net_device *dev,
                                 struct ethtool_ringparam *param,
                                 struct kernel_ethtool_ringparam *kernel_param,
                                 struct netlink_ext_ack *extack)
		{
			return;
		}
	],[
		struct ethtool_ops ipoib_ethtool_ops  = {
			.get_ringparam = ipoib_get_ringparam,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NDO_GET_COALESCE_GET_4_PARAMS, [ndo_get_coalesce get 4 parameters], [
		#include <linux/ethtool.h>

		static int ipoib_get_coalesce(struct net_device *dev,
			struct ethtool_coalesce *coal,
			struct kernel_ethtool_coalesce *kernel_coal,
			struct netlink_ext_ack *extack);
		static int ipoib_get_coalesce(struct net_device *dev,
			struct ethtool_coalesce *coal,
			struct kernel_ethtool_coalesce *kernel_coal,
			struct netlink_ext_ack *extack)
		{
			return 0;
		}
	],[
		struct ethtool_ops ipoib_ethtool_ops  = {
			.get_coalesce = ipoib_get_coalesce,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_GET_PAUSE_STATS, [get_pause_stats is defined], [
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.get_pause_stats = NULL,
		};

		return 0;
	])

        MLNX_RDMA_TEST_CASE(HAVE_GET_LINK_EXT_STATE, [.get_link_ext_state is defined], [
                #include <linux/ethtool.h>
        ],[
                const struct ethtool_ops en_ethtool_ops = {
                        .get_link_ext_state = NULL,
                };

                return 0;
        ])

	MLNX_RDMA_TEST_CASE(HAVE_TLS_OFFLOAD_RX_RESYNC_ASYNC_REQUEST_START, [net/tls.h has tls_offload_rx_resync_async_request_start], [
		#include <net/tls.h>
	],[
		tls_offload_rx_resync_async_request_start(NULL, 0, 0);

		return 0;
	])

       MLNX_RDMA_TEST_CASE(HAVE_ETHTOOL_50G_PER_LANE_LINK_MODES, [ethtool supprts 50G-pre-lane link modes], [
              #include <uapi/linux/ethtool.h>
       ],[
              const enum ethtool_link_mode_bit_indices speeds[[]] = {
		ETHTOOL_LINK_MODE_50000baseKR_Full_BIT,
		ETHTOOL_LINK_MODE_50000baseSR_Full_BIT,
		ETHTOOL_LINK_MODE_50000baseCR_Full_BIT,
		ETHTOOL_LINK_MODE_50000baseLR_ER_FR_Full_BIT,
		ETHTOOL_LINK_MODE_50000baseDR_Full_BIT,
		ETHTOOL_LINK_MODE_100000baseKR2_Full_BIT,
		ETHTOOL_LINK_MODE_100000baseSR2_Full_BIT,
		ETHTOOL_LINK_MODE_100000baseCR2_Full_BIT,
		ETHTOOL_LINK_MODE_100000baseLR2_ER2_FR2_Full_BIT,
		ETHTOOL_LINK_MODE_100000baseDR2_Full_BIT,
		ETHTOOL_LINK_MODE_200000baseKR4_Full_BIT,
		ETHTOOL_LINK_MODE_200000baseSR4_Full_BIT,
		ETHTOOL_LINK_MODE_200000baseLR4_ER4_FR4_Full_BIT,
		ETHTOOL_LINK_MODE_200000baseDR4_Full_BIT,
		ETHTOOL_LINK_MODE_200000baseCR4_Full_BIT,
		};

              return 0;
       ])

	MLNX_RDMA_TEST_CASE(HAVE_GET_RXFH_CONTEXT, [get/set_rxfh_context is defined], [
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.get_rxfh_context = NULL,
			.set_rxfh_context = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_CORE_TRACKS_CUSTOM_RSS_CONTEXTS, [kernel supports v6.11 'core tracks custom RSS contexts set'], [
		#include <linux/ethtool.h>
		#include <linux/mutex.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.modify_rxfh_context = NULL,
			.create_rxfh_context = NULL,
			.remove_rxfh_context = NULL,
		};

		DEFINE_MUTEX(_mutex);
		struct ethtool_netdev_state ens = {
			.rss_lock = _mutex,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_RSS_KEY_PER_CONTEXT, [kernel supports v6.12 'setting different RSS key for each additional context'], [
		#include <linux/ethtool.h>
	],[
		struct ethtool_ops en_ethtool_ops = {0};
		en_ethtool_ops.rxfh_per_ctx_key = 1;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ETHTOOL_NETLINK_H, [linux/ethtool_netlink.h exists], [
		#include <linux/ethtool_netlink.h>
	],[
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PCI_MSIX_CAN_ALLOC_DYN, [pci.h has pci_msix_can_alloc_dyn], [
		#include <linux/pci.h>
	],[
		bool ret;

		ret = pci_msix_can_alloc_dyn(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_IRQ_CPU_RMAP_REMOVE, [cpu_rmap.h has irq_cpu_rmap_remove], [
		#include <linux/cpu_rmap.h>
	],[
		int ret;

		ret = irq_cpu_rmap_remove(NULL,0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_IRQ_GET_EFFECTIVE_AFFINITY_MASK, [irq_get_effective_affinity_mask is defined], [
		#include <linux/irq.h>
		#include <linux/cpumask.h>
	],[
		irq_get_effective_affinity_mask(0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TC_CLS_FLOWER_OFFLOAD_HAS_STATS_FIELD_FIX, [struct tc_cls_flower_offload has stats field], [
		#include <net/pkt_cls.h>
	],[
		struct tc_cls_flower_offload *f;
		struct flow_stats stats;

		f->stats = stats;
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FOR_IFA, [for_ifa defined], [
	#include <linux/inetdevice.h>
        ],[
		struct in_device *in_dev;

		for_ifa(in_dev) {
		}

		endfor_ifa(in_dev);
        ])

	MLNX_RDMA_TEST_CASE(HAVE_NETDEV_PORT_SAME_PARENT_ID, [netdev_port_same_parent_id is defined], [
		#include <linux/netdevice.h>
	],[
		netdev_port_same_parent_id(NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NETIF_F_HW_TLS_RX, [NETIF_F_HW_TLS_RX is defined in netdev_features.h], [
		#include <linux/netdev_features.h>
	],[
		netdev_features_t tls_rx = NETIF_F_HW_TLS_RX;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TLS_OFFLOAD_DESTRUCT_WORK, [tls_offload_context_tx has destruct_work as member], [
		#include <net/tls.h>
	],[
		struct tls_offload_context_tx tls_ctx_tx;
		memset(&tls_ctx_tx.destruct_work, 0, sizeof(struct work_struct));

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NDO_UDP_TUNNEL_ADD, [ndo_add_vxlan_port is defined], [
		#include <linux/netdevice.h>

		#if IS_ENABLED(CONFIG_VXLAN)
		void add_vxlan_port(struct net_device *dev, struct udp_tunnel_info *ti);
		void add_vxlan_port(struct net_device *dev, struct udp_tunnel_info *ti)
		{
			return;
		}
		#endif

	],[
		struct net_device_ops netdev_ops;
		netdev_ops.ndo_udp_tunnel_add = add_vxlan_port;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_IPV6_DST_LOOKUP_FLOW, [if ipv6_stub has ipv6_dst_lookup_flow], [
		#include <net/addrconf.h>
		#include <net/ipv6_stubs.h>
	],[
		ipv6_stub->ipv6_dst_lookup_flow(NULL, NULL, NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_IPV6_DST_LOOKUP_FLOW_ADDR_CONF, [if ipv6_stub has ipv6_dst_lookup_flow in addrconf.h], [
		#include <net/addrconf.h>
	],[
		ipv6_stub->ipv6_dst_lookup_flow(NULL, NULL, NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_GENL_REQ_ATTR_CHECK, [HAVE_GENL_REQ_ATTR_CHECK defined], [
		#include <net/genetlink.h>
	],[
		#ifdef GENL_REQ_ATTR_CHECK
			return 0;
		#else
			#return 1;
		#endif

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NLA_POLICY_BITFIELD32, [NLA_POLICY_BITFIELD32 defined], [
		#include <net/netlink.h>
	],[
		#ifdef NLA_POLICY_BITFIELD32
			return 0;
		#else
			#return 1;
		#endif

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NLA_POLICY_NESTED, [NLA_POLICY_NESTED defined], [
		#include <net/netlink.h>
		#
		static const struct nla_policy dpll_pin_get_dump_nl_policy[[1 + 1]] = {
		    [[1]] = { .type = NLA_U32 },
		};

		static const struct nla_policy my_nested_policy[[]] = {
		    [[0]] = NLA_POLICY_NESTED(dpll_pin_get_dump_nl_policy),
		};

	],[
		#ifdef NLA_POLICY_NESTED
			return 0;
		#else
			#return 1;
		#endif

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NLA_POLICY_HAS_VALIDATION_TYPE, [nla_policy has validation_type], [
		#include <net/netlink.h>
	],[
		struct nla_policy x;
		x.validation_type = NLA_VALIDATE_MIN;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NLA_STRSCPY, [nla_strscpy exist], [
		#include <net/netlink.h>
	],[
		nla_strscpy(NULL, NULL ,0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NLA_PUT_BITFIELD32, [nla_put_bitfield32 exist], [
		#include <net/netlink.h>
	],[
		nla_put_bitfield32(NULL, 0, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NLA_NEST_START_NOFLAG, [nla_nest_start_noflag exist], [
		#include <net/netlink.h>
	],[
		nla_nest_start_noflag(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE___NLMSG_PARSE, [__nlmsg_parse exist], [
		#include <net/netlink.h>
	],[
		__nlmsg_parse(NULL, 0, NULL, 0, NULL, 0, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NLMSG_VALIDATE_DEPRECATED, [nlmsg_validate_deprecated exist], [
		#include <net/netlink.h>
	],[
		nlmsg_validate_deprecated(NULL, 0, 0, NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NLMSG_PARSE_DEPRECATED, [nlmsg_parse_deprecated exist], [
		#include <net/netlink.h>
	],[
		nlmsg_parse_deprecated(NULL, 0, NULL, 0, NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NLA_PARSE_DEPRECATED, [nla_parse_deprecated exist], [
		#include <net/netlink.h>
	],[
		nla_parse_deprecated(NULL, 0, NULL, 0, NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NLA_GET_U8_DEFAULT, [nla_get_u8_default exist], [
		#include <net/netlink.h>
	],[
		nla_get_u8_default(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NLA_POLICY_STRICT_START_TYPE, [struct nla_policy has strict_start_type], [
		#include <net/netlink.h>
	],[
		struct nla_policy x;

		x.strict_start_type = 0;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_NOTIFICATIONS_FILTERING, [kernel provides devlink notifications filtering], [
		#include <net/genetlink.h>
		#
		void spi(void *priv);
		void spi(void *priv)
		{
		}
	],[
		struct genl_family gf = {
			.sock_privs = NULL,
			.sock_priv_init = spi,
                };

		genlmsg_multicast_netns_filtered(NULL, NULL, NULL, 0, 0, 0, NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_STRUCT_GENL_SPLIT_OPS, [struct genl_ops exists], [
		#include <net/genetlink.h>
	],[
		struct genl_split_ops x;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_GENL_OPS_VALIDATE, [struct genl_ops has member validate], [
		#include <net/genetlink.h>
	],[
		struct genl_ops x;

		x.validate = 0;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_GENL_OPS_POLICY, [struct genl_ops has member policy], [
		#include <net/genetlink.h>
	],[
		struct genl_ops x;

		x.policy = NULL;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_GENL_OPS_MAXATTR, [struct genl_ops has member maxattr], [
		#include <net/genetlink.h>
	],[
		struct genl_ops x;

		x.maxattr = 0;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_GENL_FAMILY_RESV_START_OP, [struct genl_family has member resv_start_op], [
		#include <net/genetlink.h>
	],[
		struct genl_family x;

		x.resv_start_op = 0;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_GENL_FAMILY_POLICY, [struct genl_family has member policy], [
		#include <net/genetlink.h>
	],[
		struct genl_family x;

		x.policy = NULL;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PEERNET2ID_ALLOC_GET_3_PARAMS, [function peernet2id_alloc get 3 params], [
		#include <net/net_namespace.h>
	],[
		peernet2id_alloc(NULL, NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_READ_PNET_RCU, [function read_pnet_rcu is defined], [
		#include <net/net_namespace.h>
	],[
		read_pnet_rcu(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_GENL_INFO_DUMP, [function genl_info_dump is defined], [
		#include <net/genetlink.h>
	],[
		const struct genl_info *gi = genl_info_dump(NULL);
		struct genl_dumpit_info gdi;
		struct genl_info *gi2;

		gi2 = &gdi.info;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_GENL_DUMPIT_INFO, [function genl_dumpit_info is defined], [
		#include <net/genetlink.h>
	],[
		genl_dumpit_info(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NETLINK_CALLBACK_HAS_CTX, [struct netlink_callback has member ctx], [
		#include <linux/netlink.h>
	],[
		struct netlink_callback x;

		x.ctx[[0]] = 0;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NETLINK_CALLBACK_EXTACK, [struct netlink_callback has member extack], [
		#include <linux/netlink.h>
	],[
		struct netlink_callback x;

		x.extack = NULL;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NL_SET_ERR_ATTR_MISS, [macro NL_SET_ERR_ATTR_MISS is defined], [
		#include <linux/netlink.h>
	],[
		#ifdef NL_SET_ERR_ATTR_MISS
			return 0;
		#else
			#return
		#endif

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SYSFS_EMIT, [sysfs_emit is defined], [
		#include <linux/sysfs.h>
	],[
		char *buf;
		const char *output;

		sysfs_emit(buf, "%s", output);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ETHTOOL_SPRINTF, [ethtool_sprintf is defined], [
		#include <linux/ethtool.h>
	],[
		u8 data[[32]];
		u8 *p = data;
		int f_num = 0;

		ethtool_sprintf(&p, "%d", f_num);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ETHTOOL_PAUSE_STATS, [ethtool_pause_stats is defined], [
		#include <linux/ethtool.h>
	],[
		struct ethtool_pause_stats x;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ETHTOOL_RMON_HIST_RANGE, [ethtool_rmon_hist_range is defined], [
		#include <linux/ethtool.h>
	],[
		struct ethtool_rmon_hist_range x;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NDO_LINK_EXT_STATS, [get_link_ext_stats is defined], [
		#include <linux/ethtool.h>
	],[
		struct ethtool_ops x = {
			.get_link_ext_stats = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NDO_STATS_TS_GET, [get_ts_stats is defined], [
		#include <linux/ethtool.h>
	],[
		struct ethtool_ops x = {
			.get_ts_stats = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NDO_ETH_PHY_STATS, [eth_phy_stats is defined], [
		#include <linux/ethtool.h>
	],[
		struct ethtool_ops x = {
			.get_eth_phy_stats = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NDO_GET_FEC_STATS, [get_fec_stats is defined], [
		#include <linux/ethtool.h>
	],[
		struct ethtool_ops x = {
			.get_fec_stats = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SKB_SET_REDIRECTED, [skb_set_redirected is defined], [
		#include <linux/skbuff.h>
	],[
		struct sk_buff x;
		skb_set_redirected(&x, false);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_IPV6_DST_LOOKUP_TAKES_NET, [ipv6_dst_lookup takes net], [
		#include <net/addrconf.h>
	],[
		int x = ipv6_stub->ipv6_dst_lookup(NULL, NULL, NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_STATIC_ASSERT, [build_bug.h has static_assert], [
		#include <linux/build_bug.h>
                #define A 5
                #define B 6
	],[
                static_assert(A < B);

                return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_LOCKDEP_ASSERT, [lockdep.h has lockdep_assert], [
		#include <linux/lockdep.h>
	],[
                lockdep_assert(0);

                return 0;
	])
	MLNX_RDMA_TEST_CASE(HAVE_REGISTER_FIB_NOTIFIER_HAS_4_PARAMS, [register_fib_notifier has 4 params], [
		#include <net/fib_notifier.h>
	],[
		register_fib_notifier(NULL, NULL, NULL, NULL);
	])

	MLNX_RDMA_TEST_CASE(HAVE_FIB_INFO_NH, [function fib_info_nh exists], [
		#include <net/nexthop.h>
	],[
		fib_info_nh(NULL, 0);
                return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FIB6_INFO_NH_DEV, [function fib6_info_nh_dev exists], [
		#include <net/nexthop.h>
	],[
		#pragma GCC diagnostic ignored "-Warray-bounds"
		fib6_info_nh_dev(NULL);
                return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_KOBJ_TYPE_DEFAULT_GROUPS, [linux/kobject.h kobj_type has default_groups member], [
		#include <linux/kobject.h>
	],[
		struct kobj_type x = {
			.default_groups = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_LOCKDEP_UNREGISTER_KEY, [linux/lockdep.h has lockdep_unregister_key], [
		#include <linux/lockdep.h>
	],[
		lockdep_unregister_key(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_LOCKUP_ASSERT_HELD_WRITE, [linux/lockdep.h has lockdep_assert_held_write], [
		#include <linux/lockdep.h>
	],[
		#ifdef lockdep_assert_held_write
			int x = 5;
		#else
			int x
		#endif

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FIB_NH_DEV, [fib_nh has fib_nh_dev], [
		#include <net/ip_fib.h>
	],[
		struct fib_nh x = {
			.fib_nh_dev = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PAGE_DMA_ADDR, [struct page has dma_addr], [
		#include <linux/mm_types.h>
	],[
		struct page x = {
			.dma_addr = 0
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ATOMIC_PINNED_VM, [atomic_pinned_vm is defined], [
		#include <linux/mm_types.h>
	],[
		struct mm_struct x;
                atomic64_t y;
		x.pinned_vm = y;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PINNED_VM, [pinned_vm is defined], [
		#include <linux/mm_types.h>
	],[
		struct mm_struct x;
		x.pinned_vm = 0;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_RT_GW_FAMILY, [rt_gw_family is defined], [
		#include <net/route.h>
	],[
		struct rtable x = {
			.rt_gw_family = 0,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_RT_USES_GATEWAY, [rt_uses_gateway is defined], [
		#include <net/route.h>
	],[
		struct rtable x = {
			.rt_uses_gateway = 0,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_INET_ADDR_IS_ANY_SOCKADDR_STORAGE, [inet_addr_is_any takes sockaddr_storage], [
              #include <linux/inet.h>
       ],[
              struct sockaddr_storage addr;
              inet_addr_is_any(&addr);
              return 0;
       ])

	LB_CHECK_SYMBOL_EXPORT([cancel_work],
		[kernel/workqueue.c],
		[AC_DEFINE(HAVE_CANCEL_WORK_EXPORTED, 1,
			[cancel_work is exported by the kernel])],
	[])

	LB_CHECK_SYMBOL_EXPORT([unpin_user_pages_dirty_lock],
		[mm/gup.c],
		[AC_DEFINE(HAVE_UNPIN_USER_PAGES_DIRTY_LOCK_EXPORTED, 1,
			[unpin_user_pages_dirty_lock is exported by the kernel])],
	[])

	LB_CHECK_SYMBOL_EXPORT([unpin_user_page_range_dirty_lock],
		[mm/gup.c],
		[AC_DEFINE(HAVE_UNPIN_USER_PAGE_RANGE_DIRTY_LOCK_EXPORTED, 1,
			[unpin_user_page_range_dirty_lock is exported by the kernel])],
	[])

	LB_CHECK_SYMBOL_EXPORT([compat_ptr_ioctl],
		[fs/ioctl.c],
		[AC_DEFINE(HAVE_COMPAT_PTR_IOCTL_EXPORTED, 1,
			[compat_ptr_ioctl is exported by the kernel])],
	[])

	LB_CHECK_SYMBOL_EXPORT([flow_rule_match_cvlan],
		[net/core/flow_offload.c],
		[AC_DEFINE(HAVE_FLOW_RULE_MATCH_CVLAN, 1,
			[flow_rule_match_cvlan is exported by the kernel])],
	[])

	LB_CHECK_SYMBOL_EXPORT([devlink_params_publish],
		[net/core/devlink.c],
		[AC_DEFINE(HAVE_DEVLINK_PARAMS_PUBLISHED, 1,
			[devlink_params_publish is exported by the kernel])],
	[])
	LB_CHECK_SYMBOL_EXPORT([devlink_param_publish],
		[net/core/devlink.c],
		[AC_DEFINE(HAVE_DEVLINK_PARAM_PUBLISH, 1,
			[devlink_param_publish is exported by the kernel])],
	[])
	LB_CHECK_SYMBOL_EXPORT([split_page],
		[mm/page_alloc.c],
		[AC_DEFINE(HAVE_SPLIT_PAGE_EXPORTED, 1,
			[split_page is exported by the kernel])],
	[])

	LB_CHECK_SYMBOL_EXPORT([ip6_dst_hoplimit],
                [net/ipv6/output_core.c],
                [AC_DEFINE(HAVE_IP6_DST_HOPLIMIT, 1,
                        [ip6_dst_hoplimit is exported by the kernel])],
        [])

	LB_CHECK_SYMBOL_EXPORT([__ip_dev_find],
		[net/ipv4/devinet.c],
		[AC_DEFINE(HAVE___IP_DEV_FIND, 1,
			[HAVE___IP_DEV_FIND is exported by the kernel])],
	[])
	LB_CHECK_SYMBOL_EXPORT([inet_confirm_addr],
		[net/ipv4/devinet.c],
		[AC_DEFINE(HAVE_INET_CONFIRM_ADDR_EXPORTED, 1,
			[inet_confirm_addr is exported by the kernel])],
	[])

	LB_CHECK_SYMBOL_EXPORT([dev_pm_qos_update_user_latency_tolerance],
		[drivers/base/power/qos.c],
		[AC_DEFINE(HAVE_PM_QOS_UPDATE_USER_LATENCY_TOLERANCE_EXPORTED, 1,
			[dev_pm_qos_update_user_latency_tolerance is exported by the kernel])],
	[])

	LB_CHECK_SYMBOL_EXPORT([get_net_ns_by_id],
		[net/net_namespace.h],
		[AC_DEFINE(HAVE_GET_NET_NS_BY_ID_EXPORTED, 1,
			[get_net_ns_by_id is exported by the kernel])],
	[])

	MLNX_RDMA_TEST_CASE(HAVE_NDO_BRIDGE_SETLINK, [ndo_bridge_setlink is defined], [
		#include <linux/netdevice.h>

		int bridge_setlink(struct net_device *dev, struct nlmsghdr *nlh,
				   u16 flags)
		{
			return 0;
		}
	],[
		struct net_device_ops netdev_ops;
		netdev_ops.ndo_bridge_setlink = bridge_setlink;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NDO_BRIDGE_SETLINK_EXTACK, [ndo_bridge_setlink is defined], [
		#include <linux/netdevice.h>

		int bridge_setlink(struct net_device *dev, struct nlmsghdr *nlh,
				   u16 flags, struct netlink_ext_ack *extack);
		int bridge_setlink(struct net_device *dev, struct nlmsghdr *nlh,
				   u16 flags, struct netlink_ext_ack *extack)
		{
			return 0;
		}
	],[
		struct net_device_ops netdev_ops;
		netdev_ops.ndo_bridge_setlink = bridge_setlink;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NDO_GET_VF_GUID, [ndo_get_vf_guid is defined], [
		#include <linux/netdevice.h>
		#include <linux/if_link.h>

		int get_vf_guid(struct net_device *dev, int vf, struct ifla_vf_guid *node_guid,
                                                   struct ifla_vf_guid *port_guid);
		int get_vf_guid(struct net_device *dev, int vf, struct ifla_vf_guid *node_guid,
                                                   struct ifla_vf_guid *port_guid)

		{
			return 0;
		}
	],[
		struct net_device_ops netdev_ops;
		netdev_ops.ndo_get_vf_guid = get_vf_guid;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PCI_IRQ_GET_NODE, [pci_irq_get_node is defined], [
		#include <linux/pci.h>
	],[
		pci_irq_get_node(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_IDA_FREE, [idr.h has ida_free], [
		#include <linux/idr.h>
	],[
		ida_free(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_IDA_ALLOC_RANGE, [idr.h has ida_alloc_range], [
		#include <linux/idr.h>
	],[
		ida_alloc_range(NULL, 0, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_IDA_ALLOC, [ida_alloc is defined], [
		#include <linux/idr.h>
	],[
		ida_alloc(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_IDA_ALLOC_MAX, [ida_alloc_max is defined], [
		#include <linux/idr.h>
	],[
		ida_alloc_max(NULL, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_IDR_FOR_EACH_ENTRY_CONTINUE_UL, [idr_for_each_entry_continue_ul is defined], [
		#include <linux/idr.h>
	],[
		#ifdef idr_for_each_entry_continue_ul
			return 0;
		#else
			#return
		#endif

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XARRAY, [xa_array is defined], [
		#include <linux/xarray.h>
	],[
		struct xa_limit x;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XA_FOR_EACH_RANGE, [xa_for_each_range is defined], [
		#include <linux/xarray.h>
	],[
		#ifdef xa_for_each_range
			return 0;
		#else
			#return 1;
		#endif
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEFINE_SEQ_ATTRIBUTE, [DEFINE_SEQ_ATTRIBUTE is defined], [
		#include <linux/seq_file.h>
	],[
		#ifdef DEFINE_SEQ_ATTRIBUTE
			return 0;
		#else
			#return 1;
		#endif
	])

	MLNX_RDMA_TEST_CASE(HAVE_FD_FILE, [fd_file is defined], [
		#include <linux/file.h>
	],[
		struct fd file_des = EMPTY_FD;
		struct file *f = fd_file(file_des);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SCSI_CMD_TO_RQ, [scsi_cmd_to_rq is defined], [
		#include <scsi/scsi_cmnd.h>
	],[
		scsi_cmd_to_rq(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SCSI_DONE, [scsi_done is defined], [
		#include <scsi/scsi_cmnd.h>
	],[
		scsi_done(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SCSI_GET_SECTOR, [scsi_get_sector is defined], [
		#include <scsi/scsi_cmnd.h>
	],[
		scsi_get_sector(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_STRSCPY_PAD, [strscpy_pad is defined], [
		#include <linux/string.h>
	],[
		char buf[[10]];
		strscpy_pad(buf, "str", 8);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NET_NAMESPACE_GET_CONST_DEVICE, [net_namespace get const struct device], [
		#include <linux/device.h>
		static const void *net_namespace(const struct device *d) {
			void* p = NULL;
			return p;
		}

	],[
		struct class cm_class = {
			.namespace = net_namespace,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_CLASS_DEV_UEVENT_CONST_DEV, [dev_uevent get const struct device], [
		#include <linux/device.h>
		static int foo(const struct device *dev, struct kobj_uevent_env *env) {
			return 0;
		}

	],[
		struct class my_class = {
			.dev_uevent = foo,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVNODE_GET_CONST_DEVICE, [devnode get const struct device], [
		#include <linux/device.h>
		static char * foo(const struct device *dev,  umode_t *mode) {
			return NULL;
		}

	],[
		struct class my_class = {
			.devnode = foo,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_CONST_BUS_TYPE_FOR_STRUCT_DEVICE, [bus_type enty of struct device is const], [
		#include <linux/device.h>
	],[
		struct device dev;
		const struct bus_type bt;

		dev.bus = &bt;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BUS_FIND_DEVICE_GET_CONST, [bus_find_device get const], [
		#include <linux/device.h>
	],[
		const void *data;
 		bus_find_device(NULL, NULL, data, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_IPV4_NOT_POINTER_TCP_DEATH_ROW, [netns_ipv4 tcp_death_row memebr is not pointer], [
		#include <net/netns/ipv4.h>

	],[
		struct inet_timewait_death_row row;

		struct netns_ipv4 x = {
			.tcp_death_row = row,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_RTNL_NEWLINK_PARAMS,  [struct rtnl_newlink_params exists], [
		#include <net/rtnetlink.h>

	],[
		struct rtnl_newlink_params x = {};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_STRUCT_LINK_OPS_IPOIB_LINK_OPS_HAS_NETNS_REFUND, [struct rtnl_link_ops has netns_refund], [
		#include <net/rtnetlink.h>

	],[
		struct rtnl_link_ops x = {
			.netns_refund = 0,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NLMSG_FOR_EACH_ATTR_TYPE, [macro nlmsg_for_each_attr_type is defined ], [
		#include <net/netlink.h>

	],[
		#ifdef nlmsg_for_each_attr_type
			return 0;
		#else
			#return 1
		#endif

	])

	MLNX_RDMA_TEST_CASE(HAVE_EVENTFD_SIGNAL_GET_1_PARAM, [linux/eventfd.h has eventfd_signal with 1 param], [
		#include <linux/eventfd.h>
	],[

		eventfd_signal(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_STRUCT_HOP_JUMBO_HDR, [net/ipv6.h has struct  hop_jumbo_hdr], [
		#include <net/ipv6.h>
	],[

		struct hop_jumbo_hdr jumbo;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XDO_DEV_STATE_DELETE_GET_NET_DEVICE, [struct xfrmdev_ops xdo_dev_state_delete gets net_device parameter], [
		#include <linux/netdevice.h>

		static void my_xdo_dev_state_delete(struct net_device *dev, struct xfrm_state *x)
		{
		}
	],[
		struct xfrmdev_ops x = {
			.xdo_dev_state_delete = my_xdo_dev_state_delete,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NETDEV_XMIT_MORE, [netdev_xmit_more is defined], [
		#include <linux/netdevice.h>
	],[
		netdev_xmit_more();

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FOLL_LONGTERM, [FOLL_LONGTERM is defined], [
		#include <linux/mm.h>
	],[
		int x = FOLL_LONGTERM;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DMA_PCI_P2PDMA_SUPPORTED, [linux/dma-mapping.h has dma_pci_p2pdma_supported], [
		#include <linux/dma-mapping.h>
	],[
		dma_pci_p2pdma_supported(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PDE_DATA, [linux/proc_fs.h has pde_data], [
		#include <linux/proc_fs.h>
	],[
		pde_data(NULL);
		return 0;

	])

	MLNX_RDMA_TEST_CASE(HAVE_PROC_OPS_STRUCT, [struct proc_ops is defined], [
		#include <linux/proc_fs.h>
	],[
		struct proc_ops x = {
			.proc_open    = NULL,
		        .proc_read    = NULL,
		        .proc_lseek  = NULL,
		        .proc_release = NULL,
		};

		return 0;

	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MARK_DISK_DEAD, [blk_mark_disk_dead exist], [
		#include <linux/blkdev.h>
	],[
		blk_mark_disk_dead(NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DMA_ZALLOC_COHERENT, [dma-mapping.h has dma_zalloc_coherent function], [
		#include <linux/dma-mapping.h>
	],[
		dma_zalloc_coherent(NULL, 0, NULL, GFP_KERNEL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XDP_SET_FEATURES_FLAG, [xdp_set_features_flag defined], [
		#include <net/xdp.h>

	],[
		xdp_set_features_flag(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XSK_BUFF_ALLOC, [xsk_buff_alloc is defined], [
		#include <net/xdp_sock_drv.h>
	],[
		xsk_buff_alloc(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XSK_BUFF_ALLOC_BATCH, [xsk_buff_alloc_batch is defined], [
		#include <net/xdp_sock_drv.h>
	],[
		xsk_buff_alloc_batch(NULL, NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XSK_BUFF_SET_SIZE, [xsk_buff_set_size is defined], [
		#include <net/xdp_sock_drv.h>
	],[
		xsk_buff_set_size(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XSK_BUFF_GET_FRAME_DMA, [xsk_buff_xdp_get_frame_dma is defined], [
		#include <net/xdp_sock_drv.h>
	],[
		xsk_buff_xdp_get_frame_dma(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SKIP_CALLING_NOP_SYNC_OPS, [kernel supports v6.10-rc1, skip calling no-op sync ops when possible], [
		#include <net/page_pool/types.h>
	],[
		struct page_pool pp = {
			.has_init_callback = 1,
			.dma_map = 1,
			.dma_sync = 1,
			.pages_state_hold_cnt = 1,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_CONVERT_BE16_TUNNEL_FLAGS_TO_BITMAPS, [kernel supports v6.10-rc1: convert __be16 tunnel flags to bitmaps], [
		#include <net/ip_tunnels.h>
	],[
		struct ip_tunnel_parm_kern itpk = {
			.link = 1,
			.i_flags = 1,
			.o_flags = 1,
		};

		IP_TUNNEL_DECLARE_FLAGS(present) = { };
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XSK_TX_METADATA_OPS, [struct xsk_tx_metadata_ops is defined], [
		#include <net/xdp_sock.h>
	],[

		const struct xsk_tx_metadata_ops mlx5e_xsk_tx_metadata_ops = {
			.tmo_fill_timestamp             = NULL,
			.tmo_request_checksum           = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XSK_UMEM_RELEASE_ADDR_RQ, [xsk_umem_release_addr_rq is defined], [
		#include <net/xdp_sock.h>
	],[
		xsk_umem_release_addr_rq(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XSK_UMEM_ADJUST_OFFSET, [xsk_umem_adjust_offset is defined], [
		#include <net/xdp_sock.h>
	],[
		xsk_umem_adjust_offset(NULL, 0, 0);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XSK_UMEM_CONSUME_TX_GET_2_PARAMS_IN_SOCK_DRV, [net/xdp_soc_drv.h has xsk_umem_consume_tx get 2 params], [
		#include <net/xdp_sock_drv.h>
	],[
		xsk_umem_consume_tx(NULL,NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XSK_UMEM_CONSUME_TX_GET_2_PARAMS_IN_SOCK, [net/xdp_sock.h has xsk_umem_consume_tx get 2 params], [
		#include <net/xdp_sock.h>
	],[
		xsk_umem_consume_tx(NULL,NULL);
		return 0;
	])

	 MLNX_RDMA_TEST_CASE(HAVE_XDP_UMEM_CHUNK_SIZE, [chunk_size is defined], [
        		 #include <net/xdp_sock.h>
	 ],[
       		  struct xdp_umem xdp = {
                 .chunk_size = 0,
        		 };

         		return 0;
	 ])

	 MLNX_RDMA_TEST_CASE(HAVE_XDP_UMEM_FLAGS, [flags is defined], [
        		 #include <net/xdp_sock.h>
	 ],[
       		  struct xdp_umem xdp = {
                 .flags = 0,
        		 };

         		return 0;
	 ])

	MLNX_RDMA_TEST_CASE(HAVE_XDP_DO_FLUSH_MAP, [filter.h has xdp_do_flush_map], [
		#include <linux/filter.h>
	],[
		xdp_do_flush_map();

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BPF_WARN_IVALID_XDP_ACTION_GET_3_PARAMS, [filter.h has bpf_warn_invalid_xdp_action get 3 params], [
		#include <linux/filter.h>
	],[
		bpf_warn_invalid_xdp_action(NULL, NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SCSI_QUEUE_FULL, [QUEUE_FULL is defined], [
		#include <scsi/scsi.h>
	],[
		int x = QUEUE_FULL;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SCSI_BLOCK_TARGETS, [scsi_block_targets is defined], [
		#include <scsi/scsi_device.h>
	],[
		scsi_block_targets(NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ISCSIT_CONN, [iscsi_target_core.h has struct iscsit_conn], [
		#include <target/iscsi/iscsi_target_core.h>
	],[
		struct iscsit_conn c;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ISCSIT_CONN_LOGIN_SOCKADDR, [iscsit_conn has member login_sockaddr], [
		#include <target/iscsi/iscsi_target_core.h>
	],[
		struct sockaddr_storage s;
		struct iscsit_conn c = {
			.login_sockaddr = s,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ISCSIT_CONN_LOCAL_SOCKADDR, [iscsit_conn has members local_sockaddr], [
		#include <target/iscsi/iscsi_target_core.h>
	],[
		struct sockaddr_storage s;
		struct iscsit_conn c = {
			.local_sockaddr = s,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ISCSI_CONN_LOGIN_SOCKADDR, [iscsi_conn has member login_sockaddr], [
		#include <target/iscsi/iscsi_target_core.h>
	],[
		struct sockaddr_storage s;
		struct iscsi_conn c = {
			.login_sockaddr = s,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ISCSI_CONN_LOCAL_SOCKADDR, [iscsi_conn has members local_sockaddr], [
		#include <target/iscsi/iscsi_target_core.h>
	],[
		struct sockaddr_storage s;
		struct iscsi_conn c = {
			.local_sockaddr = s,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ISCSIT_CMD, [iscsi_target_core.h has struct iscsit_cmd], [
		#include <target/iscsi/iscsi_target_core.h>
	],[
		struct iscsit_cmd c;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TARGET_STOP_SESSION, [target_stop_session is defined], [
		#include <target/target_core_base.h>
		#include <target/target_core_fabric.h>
	],[
		target_stop_session(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TARGET_STOP_CMD_COUNTER, [target_stop_cmd_counter is defined], [
		#include <target/target_core_fabric.h>
	],[
		target_stop_cmd_counter(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SCSI_HOST_TEMPLATE_SHOST_GROUPS, [scsi_host_template has members shost_groups], [
		#include <scsi/scsi_host.h>
	],[
		struct scsi_host_template sh = {
			.shost_groups = NULL,
		};
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SCSI_HOST_TEMPLATE_INIT_CMD_PRIV, [scsi_host_template has member init_cmd_priv], [
		#include <scsi/scsi_host.h>
	],[
		struct scsi_host_template sh = {
			.init_cmd_priv = NULL,
		};
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SCSI_HOST_MAX_SEGMENT_SIZE, [Scsi_Host has members max_segment_size], [
		#include <scsi/scsi_host.h>
	],[
		struct Scsi_Host sh = {
			.max_segment_size = 0,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SCSI_HOST_VIRT_BOUNDARY_MASK, [Scsi_Host has members virt_boundary_mask], [
		#include <scsi/scsi_host.h>
	],[
		struct Scsi_Host sh = {
			.virt_boundary_mask = 0,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SCSI_HOST_BUSY_ITER_FN_2_ARGS, [scsi_host.h scsi_host_busy_iter fn has 2 args], [
		#include <scsi/scsi_host.h>

		bool fn(struct scsi_cmnd *scmnd, void *ctx);
		bool fn(struct scsi_cmnd *scmnd, void *ctx)
		{
			return false;
		}
	],[
		scsi_host_busy_iter(NULL, fn, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SCSI_TIMEOUT_ACTION, [scsi_host.h has enum scsi_timeout_action], [
		#include <scsi/scsi_host.h>
	],[
		enum scsi_timeout_action a = SCSI_EH_DONE;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SCSI_HOST_ALLOC_GET_CONST_SHT, [scsi_host_alloc get const struct scsi_host_template], [
		#include <scsi/scsi_host.h>
	],[
		const struct scsi_host_template t = {};

		scsi_host_alloc(&t, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SCSI_HOST_TEMPLATE_HAS_SDEV_CONFIGURE, [from 6.14, struct scsi_host_template has member sdev_configure], [
		#include <scsi/scsi_host.h>
	],[
		struct scsi_host_template sht = {
			.sdev_configure = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SE_CMD_HAS_SENSE_INFO, [struct se_cmd has member sense_info], [
		#include <target/target_core_base.h>

	],[
		struct se_cmd se = {
			.sense_info = 0,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SCSI_DEVICE_BUDGET_MAP, [scsi_device.h struct scsi_device has member budget_map], [
		#include <scsi/scsi_device.h>

		/* If it is stack, we get error that frame is too large: */
		static struct scsi_device sdev;
	],[
		sbitmap_init_node(&sdev.budget_map, 0, 0, 0, 0, false, false);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_TYPES_REQ_OPF, [enum req_opf is defined], [
		#include <linux/blk_types.h>
	],[
		enum req_opf xx = REQ_OP_DRV_OUT;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_CGROUP_BPF_RUN_FILTER_SYSCTL_7_PARAMETERS, [__cgroup_bpf_run_filter_sysctl have 7 parameters], [
		#include <linux/bpf-cgroup.h>
	],[
		return __cgroup_bpf_run_filter_sysctl(NULL, NULL, 0, NULL, NULL, NULL, 0);
	])

	MLNX_RDMA_TEST_CASE(HAVE_PCI_P2PDMA_H, [linux/pci-p2pdma.h exists], [
		#include <linux/pci-p2pdma.h>
	],[
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ASSIGN_STR_1_PARAM, [__assign_str has one param], [
		#include <trace/stages/stage6_event_callback.h>

		#undef __get_str
		#define __get_str(dst) {"abc"}

		#undef __get_dynamic_array_len
		#define __get_dynamic_array_len(dst) 3

		#undef memcpy
		#define memcpy(a,b,c)
	],[
		__assign_str(dst);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PCI_P2PDMA_UNMAP_SG, [pci_p2pdma_unmap_sg defined], [
		#include <linux/pci-p2pdma.h>
	],[
		pci_p2pdma_unmap_sg(NULL, NULL, 0, 0);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XDP_HAS_FRAGS, [struct bpf_prog_aux has xdp_has_frags as member], [
		#include <linux/bpf.h>
	],[
		struct bpf_prog_aux x = {
			.xdp_has_frags = true
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XDP_UPDATE_SKB_SHARED_INFO, [xdp_update_skb_shared_info is defined], [
		#include <net/xdp.h>
	],[
		xdp_update_skb_shared_info(NULL, 0, 0, 0, false);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XDP_METADATA_OPS_HAS_VLAN_TAG, [xdp_metadata_ops has xmo_rx_vlan_tag], [
		#include <net/xdp.h>
	],[
		const struct xdp_metadata_ops mlx5e_xdp_metadata_ops = {
			.xmo_rx_timestamp           = NULL,
			.xmo_rx_hash                = NULL,
			.xmo_rx_vlan_tag            = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XDP_GET_SHARED_INFO_FROM_BUFF, [xdp_update_skb_shared_info is defined], [
		#include <net/xdp.h>
	],[
		xdp_get_shared_info_from_buff(NULL);

		return 0;
	])

	LB_CHECK_SYMBOL_EXPORT([tcf_exts_num_actions],
		[net/sched/cls_api.c],
		[AC_DEFINE(HAVE_TCF_EXTS_NUM_ACTIONS, 1,
			[tcf_exts_num_actions is exported by the kernel])],
	[])

	LB_CHECK_SYMBOL_EXPORT([netpoll_poll_dev],
		[net/core/netpoll.c],
		[AC_DEFINE(HAVE_NETPOLL_POLL_DEV_EXPORTED, 1,
			[netpoll_poll_dev is exported by the kernel])],
	[])

	LB_CHECK_SYMBOL_EXPORT([__put_task_struct],
		[kernel/fork.c],
		[AC_DEFINE(HAVE_PUT_TASK_STRUCT_EXPORTED, 1,
			[__put_task_struct is exported by the kernel])],
	[])

	LB_CHECK_SYMBOL_EXPORT([mmput_async],
		[kernel/fork.c],
		[AC_DEFINE(HAVE_MMPUT_ASYNC_EXPORTED, 1,
			[mmput_async is exported by the kernel])],
	[])

	LB_CHECK_SYMBOL_EXPORT([get_pid_task],
		[kernel/pid.c],
		[AC_DEFINE(HAVE_GET_PID_TASK_EXPORTED, 1,
			[get_pid_task is exported by the kernel])],
	[])

	LB_CHECK_SYMBOL_EXPORT([get_task_pid],
		[kernel/pid.c],
		[AC_DEFINE(HAVE_GET_TASK_PID_EXPORTED, 1,
			[get_task_pid is exported by the kernel])],
	[])

	LB_CHECK_SYMBOL_EXPORT([mm_kobj],
		[mm/mm_init.c],
		[AC_DEFINE(HAVE_MM_KOBJ_EXPORTED, 1,
			[mm_kobj is exported by the kernel])],
	[])

	MLNX_RDMA_TEST_CASE(HAVE_BPF_PROG_ADD_RET_STRUCT, [bpf_prog_add\bfs_prog_inc functions return struct], [
		#include <linux/bpf.h>
	],[
		struct bpf_prog *prog;

		prog = bpf_prog_add(prog, 0);
		prog = bpf_prog_inc(prog);
	])

	MLNX_RDMA_TEST_CASE(HAVE_XDP_REDIRECT, [XDP_REDIRECT is defined], [
		#include <linux/bpf.h>
	],[
		enum xdp_action x = XDP_REDIRECT;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TC_CLS_FLOWER_OFFLOAD_COMMON_FIX, [struct tc_cls_flower_offload has common], [
		#include <net/pkt_cls.h>
	],[
		struct tc_cls_flower_offload x = {
			.common = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_CLS_OFFLOAD, [struct flow_cls_offload exists], [
		#include <net/flow_offload.h>
	],[
		struct flow_cls_offload x = {
			.classid = 3,
		};
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_ACTION_CT_METADATA_ORIG_DIR, [struct flow_action_entry has ct_metadata.orig_dir], [
		#include <net/flow_offload.h>
	],[
		struct flow_action_entry x = {
			.ct_metadata.orig_dir = true,
		};
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_ACTION_PTYPE, [struct flow_action_entry has ptype], [
		#include <net/flow_offload.h>
	],[
		struct flow_action_entry x = {
			.ptype = 1,
		};
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_ACTION_MPLS, [struct flow_action_entry has mpls], [
		#include <net/flow_offload.h>
	],[
		struct flow_action_entry x = {
			.mpls_push.label = 1,
		};
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_ACTION_POLICE_INDEX, [struct flow_action_entry has police.index], [
		#include <net/flow_offload.h>
	],[
		struct flow_action_entry x = {
			.police.index = 1,
		};
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_ACTION_POLICE_EXCEED, [struct flow_action_entry has police.exceed], [
		#include <net/flow_offload.h>
	],[
		struct flow_action_entry x = {
			.police.exceed.act_id = 1,
		};
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_ACTION_HW_INDEX, [struct flow_action_entry has hw_index], [
		#include <net/flow_offload.h>
	],[
		struct flow_action_entry x = {
			.hw_index = 1,
		};
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_ACTION_POLICE_RATE_PKT_PS, [struct flow_action_entry has police.rate_pkt_ps], [
		#include <net/flow_offload.h>
	],[
		struct flow_action_entry x = {
			.police.rate_pkt_ps = 1,
		};
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_RULE_MATCH_META, [flow_rule_match_meta exists], [
		#include <net/flow_offload.h>
	],[
		flow_rule_match_meta(NULL, NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_ACTION_HW_STATS_CHECK, [flow_action_hw_stats_check exists], [
		#include <net/flow_offload.h>
	],[
		#pragma GCC diagnostic ignored "-Warray-bounds"
		flow_action_hw_stats_check(NULL, NULL, 0);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_ACTION_POLICE, [FLOW_ACTION_POLICE exists], [
		#include <net/flow_offload.h>
	],[
		enum flow_action_id action = FLOW_ACTION_POLICE;
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_ACTION_CT, [FLOW_ACTION_CT exists], [
		#include <net/flow_offload.h>
	],[
		enum flow_action_id action = FLOW_ACTION_CT;
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_ACTION_REDIRECT_INGRESS, [FLOW_ACTION_REDIRECT_INGRESS exists], [
		#include <net/flow_offload.h>
	],[
		enum flow_action_id action = FLOW_ACTION_REDIRECT_INGRESS;
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ENUM_FLOW_BLOCK_BINDER_TYPE, [enum flow_block_binder_type exists], [
		#include <net/flow_offload.h>
	],[
		enum flow_block_binder_type binder_type;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_INDR_BLOCK_BIND_CB_T_7_PARAMS, [flow_indr_block_bind_cb_t has 7 parameters], [
		#include <linux/netdevice.h>
		#include <net/flow_offload.h>
		static
		int mlx5e_rep_indr_setup_cb(struct net_device *netdev, struct Qdisc *sch, void *cb_priv,
					    enum tc_setup_type type, void *type_data,
					    void *data,
					    void (*cleanup)(struct flow_block_cb *block_cb))
		{
			return 0;
		}

	],[
		flow_indr_dev_register(mlx5e_rep_indr_setup_cb, NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_INDR_BLOCK_BIND_CB_T_4_PARAMS, [flow_indr_block_bind_cb_t has 4 parameters], [
		#include <linux/netdevice.h>
		#include <net/flow_offload.h>
		static
		int mlx5e_rep_indr_setup_cb(struct net_device *netdev, void *cb_priv,
					    enum tc_setup_type type, void *type_data)
		{
			return 0;
		}

	],[
		flow_indr_dev_register(mlx5e_rep_indr_setup_cb, NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_INDR_DEV_UNREGISTER_FLOW_SETUP_CB_T, [flow_indr_dev_unregister receive flow_setup_cb_t parameter], [
		#include <linux/netdevice.h>
		#include <net/flow_offload.h>
		static int mlx5e_rep_indr_setup_tc_cb(enum tc_setup_type type,
                                      void *type_data, void *indr_priv)
		{
			return 0;
		}

	],[
		flow_indr_dev_unregister(NULL,NULL, mlx5e_rep_indr_setup_tc_cb);
		return 0;
	])


	MLNX_RDMA_TEST_CASE(HAVE_FLOW_INDR_DEV_REGISTER, [flow_indr_dev_register exists], [
		#include <linux/netdevice.h>
		#include <net/flow_offload.h>
	],[
		flow_indr_dev_register(NULL, NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_STATS_UPDATE_5_PARAMS, [flow_stats_update has 5 parameters], [
		#include <net/flow_offload.h>
	],[
		flow_stats_update(NULL, 0, 0, 0, 0);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_STATS_UPDATE_6_PARAMS, [flow_stats_update has 6 parameters], [
		#include <net/flow_offload.h>
	],[
		flow_stats_update(NULL, 0, 0, 0, 0, 0);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_CTRL_FLAG_HELPERS, [kernel provides control flag checking helpers], [
		#include <net/flow_offload.h>
	],[
		flow_rule_is_supp_control_flags(1, 1, NULL);
		flow_rule_has_control_flags(1, NULL);
		flow_rule_match_has_control_flags(NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ENCAP_CTRL_FLAG_HELPERS, [kernel provides encapsulation control flag helpers], [
		#include <net/flow_offload.h>
	],[
		flow_rule_is_supp_enc_control_flags(1, 1, NULL);
		flow_rule_has_enc_control_flags(1, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_GRO_LEGACY_MAX_SIZE, [GRO_LEGACY_MAX_SIZE defined], [
		#include <linux/netdevice.h>
	],[
		unsigned int x = GRO_LEGACY_MAX_SIZE;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_GRO_MAX_SIZE, [GRO_MAX_SIZE defined], [
		#include <linux/netdevice.h>
	],[
		unsigned long x = GRO_MAX_SIZE;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NDO_TX_TIMEOUT_GET_2_PARAMS, [ndo_tx_timeout get 2 params], [
		#include <linux/netdevice.h>

		void mlx5e_tx_timeout(struct net_device *dev, unsigned int txqueue);
		void mlx5e_tx_timeout(struct net_device *dev, unsigned int txqueue)
		{
			return;
		}
	],[
		struct net_device_ops mlx5e_netdev_ops = {
			.ndo_tx_timeout = mlx5e_tx_timeout,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NET_TC_ACT_TC_MPLS_H, [net/tc_act/tc_mpls.h exists], [
		#include <net/tc_act/tc_mpls.h>
	],[
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TCF_PEDIT_TCFP_KEYS_EX_FIX, [struct tcf_pedit has member tcfp_keys_ex], [
		#include <net/tc_act/tc_pedit.h>
	],[
		struct tcf_pedit x = {
			.tcfp_keys_ex = NULL,
		};
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TCF_PEDIT_PARMS_TCFP_KEYS_EX, [struct tcf_pedit_parms has member tcfp_keys_ex], [
		#include <net/tc_act/tc_pedit.h>
	],[
		struct tcf_pedit_parms x = {
			.tcfp_keys_ex = NULL,
		};
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ISCSI_TRANSPORT_UNBIND_CONN, [struct iscsi_transport has member unbind_conn], [
		#include <scsi/libiscsi.h>
		#include <scsi/scsi_transport_iscsi.h>
	],[
		struct iscsi_transport iscsi_iser_transport = {
			.unbind_conn = iscsi_conn_unbind,
		};
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ISCSI_HOST_REMOVE_2_PARAMS, [libiscsi.h iscsi_host_remove has 2 parameters], [
		#include <scsi/libiscsi.h>
	],[
		iscsi_host_remove(NULL, false);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ISCSI_CMD, [libiscsi.h has struct iscsi_cmd], [
		#include <scsi/libiscsi.h>
	],[
		struct iscsi_cmd c;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ISCSI_HOST_ALLOC_GET_CONST, [iscsi_host_alloc get const], [
		#include <scsi/libiscsi.h>
	],[
		const struct scsi_host_template *sht = NULL;
		iscsi_host_alloc(sht, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ISCSI_PUT_ENDPOINT, [iscsi_put_endpoint is defined], [
		#include <scsi/scsi_transport_iscsi.h>
	],[
		iscsi_put_endpoint(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_LINUX_SED_OPAL_H, [linux/sed-opal.h exists], [
		#include <linux/sed-opal.h>
	],[
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BIO_INIT_3_PARAMS, [bio.h bio_init has 3 parameters], [
		#include <linux/bio.h>
	],[
		bio_init(NULL, NULL, false);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_3_UNDERSCORE_ADDRESSABLE, [___ADDRESSABLE exists], [
		#include <linux/compiler.h>

	],[
		#ifdef ___ADDRESSABLE
			return 0;
		#else
			#return 1
		#endif

	])

	MLNX_RDMA_TEST_CASE(HAVE_RXH_XFRM_SYM_OR_XOR, [RXH_XFRM_SYM_OR_XOR exists], [
		#include <uapi/linux/ethtool.h>

	],[
		#ifdef RXH_XFRM_SYM_OR_XOR
			return 0;
		#else
			#return 1
		#endif

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_AUTO_TYPE, [__auto_type exists], [
		#include <linux/compiler.h>

		#define auto_test_no_free_ptr(p) \
		        ({ __auto_type __ptr = (p); (p) = NULL; __ptr; })
	],[
		int * a;

		auto_test_no_free_ptr(a);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_CONST_READ_ONCE_SIZE, [const __read_once_size exist], [
		#include <linux/compiler.h>
	],[
		const unsigned long tmp;
		__read_once_size(&tmp, NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE___COUNTED_BY, [compiler_types.h, compiler_attributes.h provide __counted_by macro], [
		#include <linux/compiler_types.h>
		#include <linux/compiler_attributes.h>
	],[
		#ifdef __counted_by
			return 0;
		#else
			#return 1
		#endif
	])

	MLNX_RDMA_TEST_CASE(HAVE_REGISTER_LSM_NOTIFIER, [linux/security.h has register_lsm_notifier], [
		#include <linux/security.h>
	],[
		register_lsm_notifier(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_REGISTER_BLOCKING_LSM_NOTIFIER, [linux/security.h has register_blocking_lsm_notifier], [
		#include <linux/security.h>
	],[
		register_blocking_lsm_notifier(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DMA_F_PCI_P2PDMA_SUPPORTED, [linux/dma-map-ops.h has DMA_F_PCI_P2PDMA_SUPPORTED], [
		#include <linux/dma-map-ops.h>
	],[
		struct dma_map_ops * a;
		a->flags = DMA_F_PCI_P2PDMA_SUPPORTED;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE___ATOMIC_ADD_UNLESS, [__atomic_add_unless is defined], [
		#include <linux/highmem.h>
	],[
		atomic_t x;
		__atomic_add_unless(&x, 1, 1);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ATOMIC_FETCH_ADD_UNLESS, [atomic_fetch_add_unless is defined], [
		#include <linux/highmem.h>
	],[
		atomic_t x;
		atomic_fetch_add_unless(&x, 1, 1);
	])

	MLNX_RDMA_TEST_CASE(HAVE_TCF_EXTS_STATS_UPDATE, [tcf_exts_stats_update is defined], [
		#include <net/pkt_cls.h>
	],[
		tcf_exts_stats_update(NULL, 0, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TC_ACTION_OPS_HAS_ID, [struct  tc_action_ops has id], [
		#include <net/act_api.h>
	],[
		struct tc_action_ops x = { .id = 0, };

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_LINUX_IOMMU_DMA_H, [linux/iommu-dma.h exists], [
		#include <linux/iommu.h>
		#include <linux/iommu-dma.h>
	],[
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_LINUX_UNALIGNED_H, [linux/unaligned.h exists], [
		#include <linux/unaligned.h>
	],[
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_LINUX_DEVICE_BUS_H, [linux/device/bus.h exists], [
		#include <linux/device/bus.h>
	],[
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BUS_TYPE_REMOVE_RETURN_VOID, [bus_type remove function return void], [
		#include <linux/device/bus.h>

		static void auxiliary_bus_remove(struct device *dev)
		{
		}
	],[
		struct bus_type btype = {
			.remove = auxiliary_bus_remove,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_AUX_DEV_IRQS_SYSFS, [auxiliary device IRQs sysfs exists], [
		#include <linux/auxiliary_bus.h>
		#include <linux/xarray.h>
	],[
		struct auxiliary_device ad;
		xa_init(&ad.sysfs.irqs);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_INTEGRITY_DEVICE_CAPABLE, [BLK_INTEGRITY_DEVICE_CAPABLE is defined], [
		#include <linux/blkdev.h>
	],[
		enum  blk_integrity_flags bif = BLK_INTEGRITY_DEVICE_CAPABLE;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MAX_WRITE_HINTS, [BLK_MAX_WRITE_HINTS is defined], [
		#include <linux/blkdev.h>
	],[
		int x = BLK_MAX_WRITE_HINTS;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVICE_ADD_DISK, [genhd.h has device_add_disk], [
		#include <linux/blkdev.h>
	],[
		device_add_disk(NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVICE_ADD_DISK_3_ARGS_NO_RETURN, [genhd.h has device_add_disk], [
		#include <linux/blkdev.h>
	],[
		device_add_disk(NULL, NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVICE_ADD_DISK_3_ARGS_AND_RETURN, [genhd.h has device_add_disk 3 args and must_check], [
		#include <linux/blkdev.h>
	],[
		int ret;

		ret = device_add_disk(NULL, NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_LIST_BULK_MOVE_TAIL, [list_bulk_move_tail is defined], [
		#include <linux/list.h>
	],[
		list_bulk_move_tail(NULL, NULL, NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_LIST_IS_FIRST, [list_is_first is defined], [
		#include <linux/list.h>
	],[
		list_is_first(NULL, NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SG_ALLOC_TABLE_FROM_PAGES_GET_9_PARAMS, [__sg_alloc_table_from_pages has 9 params], [
                #include <linux/scatterlist.h>
	],[
		struct scatterlist *sg;

		sg = __sg_alloc_table_from_pages(NULL, NULL, 0, 0,
					    0, 0, NULL, 0, GFP_KERNEL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SG_APPEND_TABLE, [linux/scatterlist.h has sg_append_table], [
		#include <linux/scatterlist.h>
	],[
		struct sg_append_table  sgt_append;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DMA_RESV_H, [linux/dma-resv.h exists], [
		#include <linux/dma-resv.h>
	],[
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DMA_RESV_USAGE_KERNEL, [linux/dma-resv.h has DMA_RESV_USAGE_KERNEL], [
		#include <linux/dma-resv.h>
	],[
		enum dma_resv_usage usage;

		usage = DMA_RESV_USAGE_KERNEL;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DMA_RESV_WAIT_TIMEOUT, [linux/dma-resv.h has dma_resv_wait_timeout], [
		#include <linux/dma-resv.h>
	],[
		dma_resv_wait_timeout(NULL, 0, 0, 0);
	])

	MLNX_RDMA_TEST_CASE(HAVE_DMA_RESV_EXCL_FENCE, [linux/dma-resv.h has dma_resv_excl_fence], [
		#include <linux/dma-resv.h>
	],[
		dma_resv_excl_fence(NULL);
	])

	MLNX_RDMA_TEST_CASE(HAVE_DMA_BUF_DYNAMIC_ATTACH_GET_4_PARAMS, [dma_buf_dynamic_attach get 4 params], [
		#include <linux/dma-buf.h>
	],[
		dma_buf_dynamic_attach(NULL, NULL, NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DMA_BUF_ATTACH_OPS_ALLOW_PEER2PEER, [struct dma_buf_attach_ops has allow_peer2peer], [
		#include <linux/dma-buf.h>
	],[
		struct dma_buf_attach_ops x = {
			.allow_peer2peer = 0,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NETIF_NAPI_ADD_GET_3_PARAMS, [netif_napi_add get 3 params], [
		#include <linux/netdevice.h>
	],[
		netif_napi_add(NULL, NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NETIF_NAPI_ADD_WEIGHT, [netdevice.h has netif_napi_add_weight], [
		#include <linux/netdevice.h>
	],[
		netif_napi_add_weight(NULL, NULL, NULL ,0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NETIF_IS_BAREDUDP, [netif_is_bareudp is defined], [
		#include <net/bareudp.h>
	],[
		netif_is_bareudp(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TC_SETUP_FT, [TC_TC_SETUP_FT is defined], [
		#include <linux/netdevice.h>
	],[
		enum tc_setup_type x = TC_SETUP_FT;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_UMEM_NOTIFIER_PARAM_BLOCKABLE, [ib_umem_notifier_invalidate_range_start has parameter blockable], [
		#include <linux/mmu_notifier.h>
		static int notifier(struct mmu_notifier *mn,
				    struct mm_struct *mm,
				    unsigned long start,
				    unsigned long end,
				    bool blockable) {
			return 0;
		}
	],[
		static const struct mmu_notifier_ops notifiers = {
			.invalidate_range_start = notifier
		};
	])

	MLNX_RDMA_TEST_CASE(HAVE_ISCSIT_SET_UNSOLICITED_DATAOUT, [iscsit_set_unsolicited_dataout is defined], [
		#include <target/iscsi/iscsi_transport.h>
	],[
		iscsit_set_unsolicited_dataout(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_MMU_NOTIFIER_CALL_SRCU, [mmu_notifier_call_srcu defined], [
		#include <linux/mmu_notifier.h>
	],[
		mmu_notifier_call_srcu(NULL, NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_MMU_NOTIFIER_SYNCHRONIZE, [mmu_notifier_synchronize defined], [
		#include <linux/mmu_notifier.h>
	],[
		mmu_notifier_synchronize();
		return 0;
	])


	MLNX_RDMA_TEST_CASE(HAVE_MMU_NOTIFIER_RANGE_BLOCKABLE, [mmu_notifier_range_blockable defined], [
		#include <linux/mmu_notifier.h>
	],[
                const struct mmu_notifier_range *range;

		mmu_notifier_range_blockable(range);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_MMU_NOTIFIER_OPS_HAS_FREE_NOTIFIER, [struct mmu_notifier_ops has alloc/free_notifier ], [
		#include <linux/mmu_notifier.h>
	],[
		static struct mmu_notifier_ops notifiers = {
			.free_notifier = NULL,
		};
	])

	MLNX_RDMA_TEST_CASE(HAVE_MMU_NOTIFIER_RANGE_STRUCT, [ib_umem_notifier_invalidate_range_start get struct mmu_notifier_range ], [
		#include <linux/mmu_notifier.h>
		static int notifier(struct mmu_notifier *mn,
					const struct mmu_notifier_range *range)
		{
			return 0;
		}
	],[
		static const struct mmu_notifier_ops notifiers = {
			.invalidate_range_start = notifier
		};
	])

	MLNX_RDMA_TEST_CASE(HAVE_MMU_NOTIFIER_UNREGISTER_NO_RELEASE, [mmu_notifier_unregister_no_release defined], [
		#include <linux/mmu_notifier.h>
	],[
		mmu_notifier_unregister_no_release(NULL, NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_MMU_INTERVAL_NOTIFIER, [mmu interval notifier defined], [
		#include <linux/mmu_notifier.h>
	],[
		static struct mmu_interval_notifier_ops int_notifier_ops_xx= {
			.invalidate = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE___BLKDEV_ISSUE_DISCARD, [__blkdev_issue_discard is defined], [
		#include <linux/blkdev.h>
	],[
		__blkdev_issue_discard(NULL, 0, 0, 0, 0, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE___BLKDEV_ISSUE_DISCARD_5_PARAM, [__blkdev_issue_discard has 5 params], [
		#include <linux/blkdev.h>
	],[
		__blkdev_issue_discard(NULL, 0, 0, 0, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BIO_BI_DISK, [struct bio has member bi_disk], [
		#include <linux/blk_types.h>
	],[
		struct bio b = {
			.bi_disk = NULL,
		};
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_STREAM_OPEN, [fs.h has stream_open], [
		#include <linux/fs.h>
	],[
		stream_open(NULL, NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PNV_PCI_SET_P2P, [pnv-pci.h has pnv_pci_set_p2p], [
		#include <asm/pnv-pci.h>
	],[
		pnv_pci_set_p2p(NULL, NULL, 0);

		return 0;
	])

	LB_CHECK_SYMBOL_EXPORT([interval_tree_insert],
		[lib/interval_tree.c],
		[AC_DEFINE(HAVE_INTERVAL_TREE_EXPORTED, 1,
			[interval_tree functions exported by the kernel])],
	[])

	MLNX_RDMA_TEST_CASE(HAVE_NFT_CHAIN_OFFLOAD_PRIORITY, [nft_chain_offload_priority is defined], [
		#include <net/netfilter/nf_tables_offload.h>
	],[
		nft_chain_offload_priority(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NFT_CHAIN_OFFLOAD_SUPPORT, [nft_chain_offload_support is defined], [
		#include <net/netfilter/nf_tables_offload.h>
	],[
		nft_chain_offload_support(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TC_SETUP_CB_EGDEV_REGISTER, [tc_setup_cb_egdev_register is defined], [
		#include <net/act_api.h>
	],[
		tc_setup_cb_egdev_register(NULL, NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TCF_ACTION_STATS_UPDATE, [tc_action_stats_update is defined], [
		#include <net/act_api.h>
	],[
		tcf_action_stats_update(NULL, 0, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TCF_ACTION_STATS_UPDATE_5_PARAMS, [tc_action_stats_update is defined and has 5 params], [
		#include <net/act_api.h>
	],[
		tcf_action_stats_update(NULL, 0, 0, 0, true);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_IOV_ITER_IS_BVEC_SET, [iov_iter_is_bvec is defined], [
		#include <linux/uio.h>
	],[
		struct iov_iter i;

		iov_iter_is_bvec(&i);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XDO_XFRM_ADD_STATE_GET_EXTACK, [struct xfrmdev_ops has member xdo_dev_state_add get extack], [
		#include <linux/netdevice.h>

		static int my_xdo_dev_state_add(struct xfrm_state *x,
						struct netlink_ext_ack *extack)
		{
			return 0;
		}
	],[
		struct xfrmdev_ops x = {
			.xdo_dev_state_add = my_xdo_dev_state_add,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XDO_DEV_POLICY_ADD_GET_EXTACK, [struct xfrmdev_ops has member xdo_dev_policy_add get extack], [
		#include <linux/netdevice.h>

		static int my_xdo_policy_add(struct xfrm_policy *x,
						struct netlink_ext_ack *extack)
		{
			return 0;
		}
	],[
		struct xfrmdev_ops x = {
			.xdo_dev_policy_add = my_xdo_policy_add,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XDO_DEV_POLICY_ADD, [struct xfrmdev_ops has member xdo_dev_policy_add ], [
		#include <linux/netdevice.h>
	],[
		struct xfrmdev_ops x = {
			.xdo_dev_policy_add = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XDO_DEV_STATE_UPDATE_CURLFT, [struct xfrmdev_ops has member xdo_dev_state_update_curlft ], [
		#include <linux/netdevice.h>
	],[
		struct xfrmdev_ops x = {
			.xdo_dev_state_update_curlft = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XDO_DEV_STATE_UPDATE_STATS, [struct xfrmdev_ops has member xdo_dev_state_update_stats ], [
		#include <linux/netdevice.h>
	],[
		struct xfrmdev_ops x = {
			.xdo_dev_state_update_stats = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PER_QUEUE_NETDEV_GENL_STATS, [kernel supports v6.9 per queue netdev-genl stats], [
		#include <net/netdev_queues.h>
	],[
		struct netdev_stat_ops nso = {
			.get_queue_stats_rx = NULL,
			.get_queue_stats_tx = NULL,
			.get_base_stats = NULL,
		};

		struct net_device netdev;
		netdev.stat_ops = &nso;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_IRQ_AFFINITY_DESC, [irq_affinity_desc is defined], [
		#include <linux/interrupt.h>
	],[
		struct irq_affinity_desc x;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_IRQ_UPDATE_AFFINITY_HINT, [irq_set_affinity_and_hint is defined], [
		#include <linux/interrupt.h>
	],[
		int x = irq_set_affinity_and_hint(0, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SIZE_MUL_SUB_ADD, [linux/overflow.h has size_add size_mul size_sub], [
		#include <linux/overflow.h>
	],[
		size_t a = 5;
		size_t b = 6;

		if ( size_add(a,b) && size_mul(a,b) && size_sub(a,b) )
			return 0;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_KVFREE_CALL_RCU, [function kvfree_call_rcu is defined], [
		#include <linux/rcupdate.h>
	],[
		kvfree_call_rcu(NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_KFREE_RCU_MIGHTSLEEP_MACRO, [function kfree_rcu_mightsleep is defined], [
		#include <linux/rcupdate.h>
	],[
		kfree_rcu_mightsleep(NULL);

		return 0;
	])

	# Test for new kvfree_call_rcu signature with void pointer (commit 04a522b7da3dbc083f8ae0aa1a6184b959a8f81c)
	MLNX_RDMA_TEST_CASE(HAVE_KVFREE_CALL_RCU_VOID_PTR, [kvfree_call_rcu has void ptr parameter], [
		#include <linux/rcupdate.h>
	],[
		void (*func_ptr)(struct rcu_head *, void *) = kvfree_call_rcu;
		(void)func_ptr; /* Suppress unused warning */

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE___IS_KVFREE_RCU_OFFSET, [linux/rcupdate.h defines __is_kvfree_rcu_offset], [
		#include <linux/rcupdate.h>
	],[
		#ifdef __is_kvfree_rcu_offset
			return 0;
		#else
			#return 1
		#endif

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FROM_TIMER, [from_timer macro is defined], [
		#include <linux/timer.h>
	],[
		#ifdef from_timer
			return 0;
		#else
			#return 1;
		#endif

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XDP_INIT_BUFF, [net/xdp.h has xdp_init_buff], [
		#include <net/xdp.h>
	],[
		xdp_init_buff(NULL, 0, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_UNDERSCORE_XDP_RXQ_INFO_REG, [net/xdp.h has __xdp_rxq_info_reg], [
		#include <net/xdp.h>
	],[
		__xdp_rxq_info_reg(NULL, NULL, 0, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XDP_RXQ_INFO_REG_4_PARAMS, [net/xdp.h has xdp_rxq_info_reg get 4 params], [
		#include <net/xdp.h>
	],[
		xdp_rxq_info_reg(NULL, NULL, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XDP_FRAME_BULK, [net/xdp.h struct xdp_frame_bulk exists], [
		#include <net/xdp.h>
	],[
		struct xdp_frame_bulk x;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XDP_BUFF_HAS_FLAGS, [xdp_buff has flags as member], [
		#include <net/xdp.h>
	],[
		struct xdp_buff x;
		x.flags = 0;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XDP_BUFF_HAS_FRAME_SZ, [xdp_buff has frame_sz as member], [
		#include <net/xdp.h>
	],[
		struct xdp_buff x;
		x.frame_sz = 0;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XDP_CONVERT_BUFF_TO_FRAME, [net/xdp.h has xdp_convert_buff_to_frame], [
		#include <net/xdp.h>
	],[
		xdp_convert_buff_to_frame(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XDP_CONVERT_TO_XDP_FRAME_IN_NET_XDP, [net/xdp.h has convert_to_xdp_frame], [
		#include <net/xdp.h>
	],[
		convert_to_xdp_frame(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XDP_CONVERT_TO_XDP_FRAME_IN_UEK_KABI, [net/xdp.h has convert_to_xdp_frame workaround for 5.4.17-2011.1.2.el8uek.x86_64], [
		#include <linux/uek_kabi.h>
		#include <net/xdp.h>
	],[
		convert_to_xdp_frame(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SUPPORT_IOMMUFD_VFIO_PHYS_DEVICES, [struct vfio_device_ops has iommufd support], [
		#include <linux/vfio.h>
	],[
		struct vfio_device_ops vfio_ops = {
			.bind_iommufd = NULL,
			.unbind_iommufd = NULL,
			.attach_ioas = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DETACH_IOAS_NDO, [struct vfio_device_ops has detach_ioas], [
		#include <linux/vfio.h>
	],[
		struct vfio_device_ops vfio_ops;

		vfio_ops.detach_ioas = NULL;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_VFIO_COMBINE_IOVA_RANGES, [has vfio_combine_iova_ranges exists], [
		#include <linux/vfio.h>
	],[
		vfio_combine_iova_ranges(NULL, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_VFIO_NOTIFY_IOVA_MAP, [has vfio_notify_iova_map exists], [
		#include <linux/vfio.h>
	],[
		vfio_notify_iova_map(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_VFIO_PRECOPY_INFO, [sturct vfio_precopy_info exists], [
		#include <linux/vfio.h>
	],[
		struct vfio_precopy_info info = {};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_VFIO_PCI_CORE_INIT, [vfio_pci_core_init_dev exists], [
		#include <linux/vfio_pci_core.h>
	],[
		vfio_pci_core_init_dev(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_VFIO_PCI_CORE_H, [linux/vfio_pci_core.h exists], [
		#include <linux/vfio_pci_core.h>
	],[
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NET_GRO_H, [net/gro.h is defined], [
		#include <net/gro.h>
	],[
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PAGE_POOL_PARAMS_NAPI_OLD, [net/page_pool.h struct page_pool_params has napi as member], [
		#include <net/page_pool.h>
	],[
		struct page_pool_params pp = {
			.napi = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PAGE_POOL_PARAMS_NAPI_TYPES_H, [net/page_pool/types.h struct page_pool_params has napi as member], [
		#include <net/page_pool/types.h>
	],[
		struct page_pool_params pp = {
			.napi = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PAGE_POOL_PARAMS_HAS_NETDEV, [net/page_pool/types.h struct page_pool_params has netdev as member], [
		#include <net/page_pool/types.h>
	],[
		struct page_pool_params pp = {
			.netdev = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PAGE_POOL_GET_DMA_ADDR_OLD, [net/page_pool.h page_pool_get_dma_addr defined], [
		#include <net/page_pool.h>
	],[
		page_pool_get_dma_addr(NULL);
		page_pool_set_dma_addr(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PAGE_POOL_GET_DMA_ADDR_HELPER, [net/page_pool.h page_pool_get_dma_addr defined], [
		#include <net/page_pool/helpers.h>
	],[
		page_pool_get_dma_addr(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NET_NEXTHOP_H, [net/nexthop.h is defined], [
		#include <net/nexthop.h>
	],[
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NET_PAGE_POOL_OLD_H, [net/page_pool.h is defined], [
		#include <net/page_pool.h>
	],[
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NET_PAGE_POOL_TYPES_H, [net/page_pool/types.h is defined], [
		#include <net/page_pool/types.h>
	],[
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PAGE_POOL_RELEASE_PAGE_IN_PAGE_POOL_H, [net/page_pool.h has page_pool_release_page], [
		#include <net/page_pool.h>
	],[
		page_pool_release_page(NULL, NULL);
		return 0;
	])


	MLNX_RDMA_TEST_CASE(HAVE_PAGE_POOL_RELEASE_PAGE_IN_TYPES_H, [net/page_pool/types.h has page_pool_release_page], [
		#include <net/page_pool/types.h>
	],[
		page_pool_release_page(NULL, NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PAGE_POOL_PUT_UNREFED_PAGE, [net/page_pool/types.h has page_pool_put_unrefed_page], [
		#include <net/page_pool/types.h>
	],[
		page_pool_put_unrefed_page(NULL, NULL, 0, false);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PAGE_POOL_DEFRAG_PAGE_IN_PAGE_POOL_TYPES_H, [net/page_pool/types.h has page_pool_put_defragged_page], [
		#include <net/page_pool/types.h>
	],[
		page_pool_put_defragged_page(NULL, NULL, 0, false);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PAGE_POOL_DEFRAG_PAGE_IN_PAGE_POOL_H, [net/page_pool/types.h has page_pool_put_defragged_page], [
		#include <net/page_pool.h>
	],[
		page_pool_put_defragged_page(NULL, NULL, 0, false);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PAGE_POLL_NID_CHANGED_OLD, [net/page_pool.h has page_pool_nid_changed], [
		#include <net/page_pool.h>
	],[
		page_pool_nid_changed(NULL,0);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PAGE_POLL_NID_CHANGED_HELPERS, [net/page_pool/helpers.h has page_pool_nid_changed], [
		#include <net/page_pool/helpers.h>
	],[
		page_pool_nid_changed(NULL,0);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TLS_DRIVER_CTX, [net/tls.h has tls_driver_ctx], [
		#include <net/tls.h>
	],[
		tls_driver_ctx(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TLS_OFFLOAD_RX_FORCE_RESYNC_REQUEST, [net/tls.h has tls_offload_rx_force_resync_request], [
		#include <net/tls.h>
	],[
		tls_offload_rx_force_resync_request(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_QUEUE_MAKE_REQUEST, [blk_queue_make_request existing], [
		#include <linux/blkdev.h>
	],[
		blk_queue_make_request(NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PUT_UNALIGNED_LE24, [put_unaligned_le24 existing], [
		#include <linux/unaligned/generic.h>
	],[
		put_unaligned_le24(0, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PART_STAT_H, [part_stat.h exists], [
		#include <linux/part_stat.h>
	],[
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NETDEV_BPF_XSK_BUFF_POOL, [netdev_bpf struct has pool member], [
		#include <linux/netdevice.h>
		#include <net/xsk_buff_pool.h>
	],[
		struct xsk_buff_pool *x;
		struct netdev_bpf *xdp;

		xdp->xsk.pool = x;
	])

	MLNX_RDMA_TEST_CASE(HAVE_IS_PCI_P2PDMA_PAGE_IN_MEMREMAP_H, [is_pci_p2pdma_page is defined], [
		#include <linux/memremap.h>
	],[
		is_pci_p2pdma_page(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_MM_GUP_MUST_UNSHARE_GET_3_PARAMS, [mm.h has gup_must_unshare get 3 params], [
		#include <linux/mm.h>
	],[
		gup_must_unshare(NULL, 0, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ASSERT_FAULT_LOCKED, [mm.h has assert_fault_locked], [
		#include <linux/mm.h>
	],[
		assert_fault_locked(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_IS_PCI_P2PDMA_PAGE_IN_MM_H, [is_pci_p2pdma_page is defined], [
		#include <linux/mm.h>
	],[
		is_pci_p2pdma_page(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_RELEASE_PAGES_IN_MM_H, [mm.h has release_pages], [
		#include <linux/mm.h>
	],[
		release_pages(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PAGE_FOLIO_INDEX_FIELD, [struct page has __folio_index field], [
		#include <linux/mm_types.h>
	],[
		struct page p;
		p.__folio_index = 0;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_T10_PI_PREPARE, [t10_pi_prepare is defined], [
		#include <linux/t10-pi.h>
	],[
		t10_pi_prepare(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MQ_BUSY_TAG_ITER_FN_BOOL_2_PARAMS, [linux/blk-mq.h has busy_tag_iter_fn return bool], [
		#include <linux/blk-mq.h>

		static bool
		nvme_cancel_request(struct request *req, void *data) {
			return true;
		}
	],[
		busy_tag_iter_fn *fn = nvme_cancel_request;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MQ_BUSY_TAG_ITER_FN_BOOL_3_PARAMS, [linux/blk-mq.h has busy_tag_iter_fn return bool], [
		#include <linux/blk-mq.h>

		static bool
		nvme_cancel_request(struct request *req, void *data, bool reserved) {
			return true;
		}
	],[
		busy_tag_iter_fn *fn = nvme_cancel_request;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MQ_OPS_POLL_1_ARG, [struct blk_mq_ops has poll 1 arg], [
		#include <linux/blk-mq.h>

		static int nvme_poll(struct blk_mq_hw_ctx *hctx) {
			return 0;
		}
	],[
		struct blk_mq_ops ops = {
			.poll = nvme_poll,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BITMAP_ZALLOC_NODE, [bitmap_zalloc_node is defined], [
	#include <linux/bitmap.h>
	],[
		unsigned long *bmap;

		bmap = bitmap_zalloc_node(1, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DMA_MAP_SGTABLE, [dma-mapping.h has dma_map_sgtable], [
		#include <linux/dma-mapping.h>
	],[
		int i = dma_map_sgtable(NULL, NULL, 0, 0);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TC_HTB_COMMAND_HAS_MOVED_QID, [struct tc_htb_command has moved_qid], [
		#include <net/pkt_cls.h>
	],[
		struct tc_htb_qopt_offload *x;
		x->moved_qid = 0;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MQ_COMPLETE_REQUEST_SYNC, [blk-mq.h has blk_mq_complete_request_sync], [
		#include <linux/blk-mq.h>
	],[
		blk_mq_complete_request_sync(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_TYPES_REQ_HIPRI, [REQ_HIPRI is defined], [
		#include <linux/blk_types.h>
	],[
		int x = REQ_HIPRI;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TASKLET_SETUP, [interrupt.h has tasklet_setup], [
		#include <linux/interrupt.h>
	],[
		tasklet_setup(NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLKDEV_DMA_MAP_BVEC, [dma_map_bvec exist], [
		#include <linux/blkdev.h>
		#include <linux/dma-mapping.h>
	],[
		struct bio_vec bv = {};

		dma_map_bvec(NULL, &bv, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_INDR_BLOCK_CB_ALLOC, [flow_indr_block_cb_alloc exist], [
		#include <net/flow_offload.h>
	],[
		flow_indr_block_cb_alloc(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_BLOCK_CB, [struct flow_block_cb exist], [
		#include <net/flow_offload.h>
	],[
		struct flow_block_cb a;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SG_ALLOC_TABLE_CHAINED_NENTS_FIRST_CHUNK_PARAM, [sg_alloc_table_chained has nents_first_chunk parameter], [
		#include <linux/scatterlist.h>
	],[
		sg_alloc_table_chained(NULL, 0, NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_REQUEST_TO_QC_T, [linux/blk-mq.h has request_to_qc_t], [
		#include <linux/blk-mq.h>
	],[
		request_to_qc_t(NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MQ_REQUEST_COMPLETED, [linux/blk-mq.h has blk_mq_request_completed], [
		#include <linux/blk-mq.h>
	],[
		blk_mq_request_completed(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MQ_TAGSET_WAIT_COMPLETED_REQUEST, [linux/blk-mq.h has blk_mq_tagset_wait_completed_request], [
		#include <linux/blk-mq.h>
	],[
		blk_mq_tagset_wait_completed_request(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XPO_SECURE_PORT_NO_RETURN, [xpo_secure_port is defined and returns void], [
		#include <linux/sunrpc/svc_xprt.h>

		void secure_port(struct svc_rqst *rqstp)
		{
			return;
		}
	],[
		struct svc_xprt_ops check_rdma_ops;

		check_rdma_ops.xpo_secure_port = secure_port;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SVC_RQST_RQ_XPRT_HLEN, [struct svc_rqst has rq_xprt_hlen], [
		#include <linux/sunrpc/svc.h>
	],[
		struct svc_rqst rqst;

		rqst.rq_xprt_hlen = 0;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SVC_SERV_SV_CB_LIST_LWQ, [struct svc_serv has sv_cb_list], [
		#include <linux/sunrpc/svc.h>
	],[
		struct svc_serv serv;
		struct lwq      list;

		serv.sv_cb_list = list;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SVC_SERV_SV_CB_LIST_LIST_HEAD, [struct svc_serv has sv_cb_list], [
		#include <linux/sunrpc/svc.h>
	],[
		struct svc_serv serv;
		struct list_head list;

		serv.sv_cb_list = list;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_RPCSVC_MAXPAGES, [RPCSVC_MAXPAGES macro is defined], [
		#include <linux/sunrpc/svc.h>
	],[
			int pages = RPCSVC_MAXPAGES;

			return 0;
	])

	LB_CHECK_SYMBOL_EXPORT([svc_pool_wake_idle_thread],
		[net/sunrpc/svc.c],
		[AC_DEFINE(HAVE_SVC_POOL_WAKE_IDLE_THREAD, 1,
			[svc_pool_wake_idle_thread is exported by the kernel])],
	[])

	MLNX_RDMA_TEST_CASE(HAVE_XPRT_OPS_SEND_REQUEST_RQST_ARG, [*send_request has 'struct rpc_rqst *req' as a param], [
		#include <linux/sunrpc/xprt.h>

		int send_request(struct rpc_rqst *req);
		int send_request(struct rpc_rqst *req)
		{
			return 0;
		}
	],[
		struct rpc_xprt_ops ops;

		ops.send_request = send_request;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XPRT_REQUEST_GET_CONG, [get cong request], [
		#include <linux/sunrpc/xprt.h>
	],[
		return xprt_request_get_cong(NULL, NULL);
	])

	MLNX_RDMA_TEST_CASE(HAVE_SVC_XPRT_XPO_SECURE_PORT, [struct svc_xprt_ops 'xpo_secure_port' field], [
		#include <linux/sunrpc/svc_xprt.h>
	],[
		struct svc_xprt_ops dummy_svc_ops;

		dummy_svc_ops.xpo_secure_port = NULL;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SVC_XPRT_XPO_PREP_REPLY_HDR, [struct svc_xprt_ops 'xpo_prep_reply_hdr' field], [
		#include <linux/sunrpc/svc_xprt.h>
	],[
		struct svc_xprt_ops dummy_svc_ops;

		dummy_svc_ops.xpo_prep_reply_hdr = NULL;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XPO_READ_PAYLOAD, [struct svc_xprt_ops has 'xpo_read_payload' field], [
		#include <linux/sunrpc/svc_xprt.h>
	],[
		struct svc_xprt_ops dummy_svc_ops;

		dummy_svc_ops.xpo_read_payload = NULL;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XPO_RESULT_PAYLOAD, [struct svc_xprt_ops has 'xpo_result_payload' field], [
		#include <linux/sunrpc/svc_xprt.h>
	],[
		struct svc_xprt_ops dummy_svc_ops;

		dummy_svc_ops.xpo_result_payload = NULL;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XPO_RELEASE_CTXT, [struct svc_xprt_ops has 'xpo_release_ctxt' field], [
		#include <linux/sunrpc/svc_xprt.h>
	],[
		struct svc_xprt_ops dummy_svc_ops;

		dummy_svc_ops.xpo_release_ctxt = NULL;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_RPC_XPRT_OPS_SET_RETRANS_TIMEOUT, [struct rpc_xprt_ops has 'set_retrans_timeout' field], [
		#include <linux/sunrpc/xprt.h>
	],[
		struct rpc_xprt_ops dummy_ops;

		dummy_ops.set_retrans_timeout = NULL;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_RPC_XPRT_OPS_WAIT_FOR_REPLY_REQUEST, [struct rpc_xprt_ops has 'wait_for_reply_request' field], [
		#include <linux/sunrpc/xprt.h>
	],[
		struct rpc_xprt_ops dummy_ops;

		dummy_ops.wait_for_reply_request = NULL;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XPRT_QUEUE_LOCK, [struct rpc_xprt has 'queue_lock' field], [
		#include <linux/sunrpc/xprt.h>
	],[
		spinlock_t *dummy_lock;
		struct rpc_xprt dummy_xprt;

		dummy_lock = &dummy_xprt.queue_lock;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XPRT_WAIT_FOR_BUFFER_SPACE_RQST_ARG, [xprt_wait_for_buffer_space has xprt as a parameter], [
		#include <linux/sunrpc/xprt.h>

		/* If it is stack, we get error that frame is too large: */
		static struct rpc_xprt xprt;
	],[
		xprt_wait_for_buffer_space(&xprt);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_RPC_XPRT_RECV_LOCK, [struct rpc_xprt has 'recv_lock' field], [
		#include <linux/sunrpc/xprt.h>
	],[
		spinlock_t *dummy_lock;
		struct rpc_xprt dummy_xprt;

		dummy_lock = &dummy_xprt.recv_lock;

		return 0;
	])


	MLNX_RDMA_TEST_CASE(HAVE_RPC_XPRT_XPRT_CLASS, [struct rpc_xprt has 'xprt_class' field], [
		#include <linux/sunrpc/xprt.h>
	],[
		struct rpc_xprt dummy_xprt;

		dummy_xprt.xprt_class = NULL;

		return 0;
	])

	LB_CHECK_SYMBOL_EXPORT([xprt_reconnect_delay],
		[net/sunrpc/xprt.c],
		[AC_DEFINE(HAVE_XPRT_RECONNECT_DELAY, 1,
			[xprt_reconnect_delay is exported by the kernel])],
	[])

	MLNX_RDMA_TEST_CASE(HAVE_RPC_XPRT_OPS_BC_NUM_SLOTS, [struct rpc_xprt_ops has 'bc_num_slots' field], [
		#include <linux/sunrpc/xprt.h>
	],[
		struct rpc_xprt_ops dummy_ops;

		dummy_ops.bc_num_slots = NULL;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_RPC_XPRT_OPS_BC_UP, [struct rpc_xprt_ops has 'bc_up' field], [
		#include <linux/sunrpc/xprt.h>
	],[
		struct rpc_xprt_ops dummy_ops;

		dummy_ops.bc_up = NULL;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XPRT_CLASS_NETID, [struct xprt_class has 'netid' field], [
		#include <linux/sunrpc/xprt.h>
	],[
		struct xprt_class xc;

		xc.netid;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SYSCTL_ZERO_ENABLED, [linux/sysctl.h has SYSCTL_ZERO defined], [
		#include <linux/sysctl.h>
	],[
		void *dummy;

		dummy = SYSCTL_ZERO;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_CTL_TABLE_CHILD, [struct ctl_table have "child" field], [
		#include <linux/sysctl.h>
	],[
		 struct ctl_table dummy_table;

		dummy_table.child = NULL;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XDRBUF_SPARSE_PAGES, [XDRBUF_SPARSE_PAGES has defined in linux/sunrpc/xdr.h], [
		#include <linux/sunrpc/xdr.h>
	],[
		int dummy;

		dummy = XDRBUF_SPARSE_PAGES;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XDR_INIT_ENCODE_RQST_ARG, [xdr_init_encode has rqst as a parameter], [
		#include <linux/sunrpc/xdr.h>
	],[
		struct rpc_rqst *rqst = NULL;

		xdr_init_encode(NULL, NULL, NULL, rqst);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XDR_INIT_DECODE_RQST_ARG, [xdr_init_decode has rqst as a parameter], [
		#include <linux/sunrpc/xdr.h>
	],[
		struct rpc_rqst *rqst = NULL;

		xdr_init_decode(NULL, NULL, NULL, rqst);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SVC_RDMA_RECV_CTXT_RC_STREAM, [struct svc_rdma_recv_ctxt has 'rc_stream' field], [
		#include <linux/sunrpc/xdr.h>
		#include <linux/sunrpc/svc_rdma.h>
	],[
		struct xdr_stream dummy_stream;
		struct svc_rdma_recv_ctxt dummy_rctxt;

		dummy_rctxt.rc_stream = dummy_stream;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SVCXPRT_RDMA_SC_PENDING_RECVS, [struct svcxprt_rdma has 'sc_pending_recvs' field], [
		#include <linux/sunrpc/svc_rdma.h>
	],[
		struct svcxprt_rdma dummy_rdma;

		dummy_rdma.sc_pending_recvs = 0;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XDR_ENCODE_RDMA_SEGMENT, [xdr_encode_rdma_segment has defined], [
		#include <linux/sunrpc/xdr.h>
		#include <linux/sunrpc/rpc_rdma.h>
	],[
		xdr_encode_rdma_segment(NULL, 0, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_RPCRDMA_RN_REGISTER, [rpcrdma_rn_register has defined], [
		#include <linux/sunrpc/rdma_rn.h>
	],[
		rpcrdma_rn_register(NULL, NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XDR_DECODE_RDMA_SEGMENT, [xdr_decode_rdma_segment has defined], [
		#include <linux/sunrpc/xdr.h>
		#include <linux/sunrpc/rpc_rdma.h>
	],[
		xdr_decode_rdma_segment(NULL, 0, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XDR_STREAM_ENCODE_ITEM_ABSENT, [xdr_stream_encode_item_absent has defined], [
		#include <linux/sunrpc/xdr.h>
	],[
		xdr_stream_encode_item_absent(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XDR_ITEM_IS_ABSENT, [xdr_item_is_absent has defined], [
		#include <linux/sunrpc/xdr.h>
	],[
		xdr_item_is_absent(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XDR_BUF_SUBSEGMENT_CONST, [xdr_buf_subsegment get const], [
		#include <linux/sunrpc/xdr.h>
	],[
		const struct xdr_buf *dummy;
		xdr_buf_subsegment(dummy, NULL, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SVC_XPRT_IS_DEAD, [svc_xprt_is_dead has defined], [
		#include <linux/sunrpc/svc_xprt.h>
	],[
		svc_xprt_is_dead(NULL);

        return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SVC_RDMA_RELEASE_RQST, [svc_rdma_release_rqst has externed], [
		#include <linux/sunrpc/svc_rdma.h>
	],[
		svc_rdma_release_rqst(NULL);

        return 0;
	])

	LB_CHECK_SYMBOL_EXPORT([xprt_add_backlog],
		[net/sunrpc/xprt.c],
		[AC_DEFINE(HAVE_XPRT_ADD_BACKLOG, 1,
			[xprt_add_backlog is exported by the sunrpc core])],
	[])

	LB_CHECK_SYMBOL_EXPORT([xprt_lock_connect],
		[net/sunrpc/xprt.c],
		[AC_DEFINE(HAVE_XPRT_LOCK_CONNECT, 1,
			[xprt_lock_connect is exported by the sunrpc core])],
	[])

	LB_CHECK_SYMBOL_EXPORT([svc_xprt_deferred_close],
		[net/sunrpc/svc_xprt.c],
		[AC_DEFINE(HAVE_SVC_XPRT_DEFERRED_CLOSE, 1,
			[svc_xprt_deferred_close is exported by the sunrpc core])],
	[])

	LB_CHECK_SYMBOL_EXPORT([svc_xprt_received],
		[net/sunrpc/svc_xprt.c],
		[AC_DEFINE(HAVE_SVC_XPRT_RECEIVED, 1,
			[svc_xprt_received is exported by the sunrpc core])],
	[])

	LB_CHECK_SYMBOL_EXPORT([svc_xprt_close],
		[net/sunrpc/svc_xprt.c],
		[AC_DEFINE(HAVE_SVC_XPRT_CLOSE, 1,
			[svc_xprt_close is exported by the sunrpc core])],
	[])

	MLNX_RDMA_TEST_CASE(HAVE_TRACE_RPCRDMA_H, [rpcrdma.h exists], [
		#include <linux/sunrpc/svc_rdma.h>
		#include "../../net/sunrpc/xprtrdma/xprt_rdma.h"

		#include <trace/events/rpcrdma.h>
	],[
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SVC_RDMA_PCL, [struct svc_rdma_pcl exists], [
		#include <linux/sunrpc/xdr.h>
		#include <linux/sunrpc/svc_rdma_pcl.h>
	],[
		struct svc_rdma_pcl *pcl;

		pcl = NULL;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_CLASS_CREATE_GET_1_PARAM, [class_create get 1 param], [
		#include <linux/device/class.h>
	],[
	        static struct class *uverbs_class;
		uverbs_class = class_create("Test");

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SHOW_CLASS_ATTR_STRING_GET_CONST, [show_class_attr_string get const], [
		#include <linux/device/class.h>
	],[
	        const struct class *uverbs_class;
	        const struct class_attribute *uverbs_attr;

		show_class_attr_string(uverbs_class, uverbs_attr, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_CLASS_REGISTER_GET_CONST, [class_register get const], [
		#include <linux/device/class.h>
	],[
	        const struct class *c = NULL;
		int ret;

		ret = class_register(c);

		return ret;
	])

	MLNX_RDMA_TEST_CASE(HAVE___NETDEV_TX_SENT_QUEUE, [netdevice.h has __netdev_tx_sent_queue], [
		#include <linux/netdevice.h>
	],[
		#pragma GCC diagnostic ignored "-Warray-bounds"
		__netdev_tx_sent_queue(NULL, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_MSI_MAP_TMP, [msi_map exists], [
		#include <linux/msi_api.h>
	],[
		struct msi_map x;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_DISSECTOR_KEY_META, [FLOW_DISSECTOR_KEY_META is defined], [
		#include <net/flow_dissector.h>
	],[
		enum flow_dissector_key_id keyid = FLOW_DISSECTOR_KEY_META;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NETIF_IS_GENEVE, [netif_is_geneve is defined], [
		#include <uapi/linux/if.h>
		#include <net/geneve.h>
	],[
		netif_is_geneve(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NETIF_IS_GRETAP, [netif_is_gretap is defined], [
		#include <uapi/linux/if.h>
		#include <net/gre.h>
	],[
		struct net_device dev = {};

		netif_is_gretap(&dev);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NETIF_IS_VXLAN, [netif_is_vxlan is defined], [
		#include <net/vxlan.h>
	],[
		struct net_device dev = {};

		netif_is_vxlan(&dev);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_LINUX_MEI_UUID_H, [uapi/linux/mei_uuid.h is exists], [
		#include <uapi/linux/mei_uuid.h>
	],[
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NET_BAREUDP_H, [net/bareudp.h is exists], [
		#include <net/bareudp.h>
	],[
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_STRUCT_PSAMPLE_METADATA, [net/psample.h has struct psample_metadata], [
		#include <linux/skbuff.h>
		#include <net/psample.h>
	],[
		struct psample_metadata *x;
		x->trunc_size = 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NETIF_IS_BAREUDP, [netif_is_bareudp is defined], [
		#include <net/bareudp.h>
	],[
		netif_is_bareudp(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLKDEV_REQ_BVEC, [linux/blkdev.h has req_bvec], [
		#include <linux/blkdev.h>
		#include <linux/blk-mq.h>
	],[
		req_bvec(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PCI_P2PDMA_MAP_SG_ATTRS, [pci_p2pdma_map_sg_attrs defined], [
		#include <linux/pci-p2pdma.h>
	],[
		pci_p2pdma_map_sg_attrs(NULL, NULL, 0, 0, 0);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_UAPI_LINUX_NVME_PASSTHRU_CMD64, [uapi/linux/nvme_ioctl.h has struct nvme_passthru_cmd64], [
		#include <linux/nvme_ioctl.h>
		#include <linux/types.h>
		#include <uapi/asm-generic/ioctl.h>
	],[
		struct nvme_passthru_cmd64 cmd = {};
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_REQUEST_QUEUE_BACKING_DEV_INFO, [struct request_queue has backing_dev_info], [
		#include <linux/blkdev.h>
	],[
		struct backing_dev_info *bdi = NULL;
		struct request_queue rq = {
			.backing_dev_info = bdi,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SKB_QUEUE_EMPTY_LOCKLESS, [linux/skbuff.h has skb_queue_empty_lockless], [
		#include <linux/skbuff.h>
	],[
		skb_queue_empty_lockless(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PCI_DRIVER_MANAGED_DMA, [struct pci_driver has member driver_managed_dma], [
		#include <linux/pci.h>
	],[
		struct pci_driver core_driver = {
			.driver_managed_dma = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PCIE_ASPM_ENABLED, [linux/pci.h has pcie_aspm_enabled], [
		#include <linux/pci.h>
	],[
		pcie_aspm_enabled(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_MACSEC_H, [net/macsec.h exists], [
		#include <net/macsec.h>
	],[
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XDP_SOCK_DRV_H, [net/xdp_sock_drv.h exists], [
		#include <net/xdp_sock_drv.h>
	],[
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XSK_BUFF_DMA_SYNC_FOR_CPU_2_PARAMS, [xsk_buff_dma_sync_for_cpu get 2 params], [
		#include <net/xdp_sock_drv.h>
	],[
		xsk_buff_dma_sync_for_cpu(NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_UNITS_H, [include/linux/units.h exists], [
		#include <linux/units.h>
	],[
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_REMOVE_SENTINEL_FROM_CTL_TABLE, [v6.6 remove sentinel from ctl_table array is supported], [
		#include <linux/sysctl.h>
	],[
		struct ctl_table_header cth;

		cth.ctl_table_size = 1;
		register_sysctl_sz(NULL, NULL, 1);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PROC_HANDLER_CONST_PARAM, [proc_handler has const parameter], [
		#include <linux/sysctl.h>
	],[
		struct ctl_table dummy_table;
		const struct ctl_table *ctl = &dummy_table;

		dummy_table.proc_handler(ctl, 0, NULL, NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLKDEV_BIO_INTEGRITY_BYTES, [linux/blkdev.h has bio_integrity_bytes], [
		#include <linux/blkdev.h>
	],[
		bio_integrity_bytes(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ESP_OUTPUT_FILL_TRAILER, [esp_output_fill_trailer is defined], [
		#include <net/xfrm.h>
		#include <net/esp.h>
	],[
		esp_output_fill_trailer(NULL, 0, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_QUEUE_MAX_ACTIVE_ZONES, [blk_queue_max_active_zones exist], [
		#include <linux/blkdev.h>
	],[
		blk_queue_max_active_zones(NULL, 0);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SET_CAPACITY_REVALIDATE_AND_NOTIFY, [genhd.h has set_capacity_revalidate_and_notify], [
		#include <linux/blkdev.h>
	],[
		set_capacity_revalidate_and_notify(NULL, 0, false);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLOCK_DEVICE_OPERATIONS_SUBMIT_BIO, [struct block_device_operations has submit_bio], [
		#include <linux/blkdev.h>
	],[
		struct block_device_operations ops = {
			.submit_bio = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_QUEUE_SPLIT_1_PARAM, [blk_queue_split has 1 param], [
		#include <linux/blkdev.h>
	],[
		blk_queue_split(NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BIO_SPLIT_TO_LIMITS, [blkdev.h has bio_split_to_limits], [
		#include <linux/blkdev.h>
	],[
		bio_split_to_limits(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SUBMIT_BIO_NOACCT, [submit_bio_noacct exist], [
		#include <linux/blkdev.h>
	],[
		submit_bio_noacct(NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_SHOULD_FAKE_TIMEOUT, [linux/blk-mq.h has blk_should_fake_timeout], [
		#include <linux/blk-mq.h>
	],[
		blk_should_fake_timeout(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MQ_COMPLETE_REQUEST_REMOTE, [linux/blk-mq.h has blk_mq_complete_request_remote], [
		#include <linux/blk-mq.h>
	],[
		blk_mq_complete_request_remote(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TRACE_BLOCK_BIO_COMPLETE_2_PARAM, [trace_block_bio_complete has 2 param], [
		#include <trace/events/block.h>
	],[
		trace_block_bio_complete(NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_IP_SOCK_SET_TOS, [net/ip.h has ip_sock_set_tos], [
		#include <net/ip.h>
	],[
		ip_sock_set_tos(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SKB_TCP_ALL_HEADERS, [linux/tcp.h has skb_tcp_all_headers], [
		#include <linux/tcp.h>
	],[
		skb_tcp_all_headers(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TCP_SOCK_SET_SYNCNT, [linux/tcp.h has tcp_sock_set_syncnt], [
		#include <linux/tcp.h>
	],[
		tcp_sock_set_syncnt(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TCP_SOCK_SET_NODELAY, [linux/tcp.h has tcp_sock_set_nodelay], [
		#include <linux/tcp.h>
	],[
		tcp_sock_set_nodelay(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLKDEV_ISSUE_FLUSH_2_PARAM, [blkdev_issue_flush has 2 params], [
		#include <linux/blkdev.h>
	],[
		blkdev_issue_flush(NULL, 0);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SOCK_NO_LINGER, [net/sock.h has sock_no_linger], [
		#include <net/sock.h>
	],[
		sock_no_linger(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SOCK_SET_PRIORITY, [net/sock.h has sock_set_priority], [
		#include <net/sock.h>
	],[
		sock_set_priority(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SOCK_SET_REUSEADDR, [net/sock.h has sock_set_reuseaddr], [
		#include <net/sock.h>
	],[
		sock_set_reuseaddr(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SENDPAGE_OK, [linux/net.h has sendpage_ok], [
		#include <linux/net.h>
	],[
		sendpage_ok(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ENUM_CSID_X86_ART, [clocksource_ids has CSID_X86_ART], [
		#include <linux/clocksource_ids.h>
	],[
		int tmp = CSID_X86_ART;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PTP_FIND_PIN_UNLOCK, [ptp_find_pin_unlocked is defined], [
		#include <linux/ptp_clock_kernel.h>
	],[
		ptp_find_pin_unlocked(NULL, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XFRM_OFFLOAD_PACKET, [XFRM_OFFLOAD_PACKET is defined], [
		#include <uapi/linux/xfrm.h>
	],[
		int a = XFRM_OFFLOAD_PACKET;
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_XFRM_OFFLOAD_INNER_IPPROTO, [struct xfrm_offload has inner_ipproto], [
		#include <net/xfrm.h>
	],[
		struct xfrm_offload xo = {
			.inner_ipproto = 4,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BD_SET_NR_SECTORS, [genhd.h has bd_set_nr_sectors], [
		#include <linux/blkdev.h>
	],[
		bd_set_nr_sectors(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ALLOC_WORKQUEUE_NOPROF, [alloc_workqueue_noprof exists], [
		#include <linux/workqueue.h>
	],[
		struct workqueue_struct *wq;

		wq = alloc_workqueue_noprof("test", 0, 1);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ALLOC_WORKQUEUE_MACRO, [alloc_workqueue is a macro], [
		#include <linux/workqueue.h>
	],[
		#ifdef alloc_workqueue
			return 0;
		#else
			#return 1
		#endif
	])

	MLNX_RDMA_TEST_CASE(HAVE_QUEUE_FLAG_STABLE_WRITES, [QUEUE_FLAG_STABLE_WRITES is defined], [
		#include <linux/blkdev.h>
	],[
		int x = QUEUE_FLAG_STABLE_WRITES;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_REVALIDATE_DISK_SIZE, [genhd.h has revalidate_disk_size], [
		#include <linux/blkdev.h>
	],[
		revalidate_disk_size(NULL, false);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MQ_SET_REQUEST_COMPLETE, [linux/blk-mq.h has blk_mq_set_request_complete], [
		#include <linux/blk-mq.h>
	],[
		blk_mq_set_request_complete(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_ALLOC_QUEUE_RH, [linux/blkdev.h has blk_alloc_queue_rh], [
		#include <linux/blkdev.h>
	],[
		blk_alloc_queue_rh(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_REQUEST_BDEV, [blkdev.h struct request has block_device], [
		#include <linux/blkdev.h>
		#include <linux/blk-mq.h>
	],[
		struct block_device *bdev = NULL;
		struct request rq = { .part = bdev };
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLKDEV_ISSUE_FLUSH_1_PARAM, [blkdev_issue_flush has 1 params], [
		#include <linux/blkdev.h>
	],[
		blkdev_issue_flush(NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BIO_MAX_SEGS, [if bio.h has bio_max_segs], [
		#include <linux/bio.h>
	],[
		bio_max_segs(0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TRACE_BLOCK_BIO_REMAP_4_PARAM, [trace_block_bio_remap has 4 param], [
		#include <trace/events/block.h>
	],[
		trace_block_bio_remap(NULL, NULL, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BD_SET_SIZE, [genhd.h has bd_set_size], [
		#include <linux/blkdev.h>
	],[
		bd_set_size(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_EXECUTE_RQ_NOWAIT_5_PARAM, [blk_execute_rq_nowait has 5 params], [
		#include <linux/blkdev.h>
	],[
		blk_execute_rq_nowait(NULL, NULL, NULL, 0, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_EXECUTE_RQ_NOWAIT_4_PARAM, [blk_execute_rq_nowait has 4 params], [
		#include <linux/blk-mq.h>
		#include <linux/blkdev.h>
	],[
		blk_execute_rq_nowait(NULL, NULL, 0, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_EXECUTE_RQ_NOWAIT_3_PARAM, [blk_execute_rq_nowait has 3 params], [
		#include <linux/blk-mq.h>
	],[
		blk_execute_rq_nowait(NULL, 0, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_EXECUTE_RQ_NOWAIT_2_PARAM, [blk_execute_rq_nowait has 2 params], [
		#include <linux/blk-mq.h>
	],[
		blk_execute_rq_nowait(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_EXECUTE_RQ_4_PARAM, [blk_execute_rq  has 4 params], [
		#include <linux/blkdev.h>
	],[
		blk_execute_rq(NULL, NULL, NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ENUM_BIO_REMAPPED, [struct enum has member BIO_REMAPPED], [
		#include <linux/blk_types.h>
	],[
		int tmp = BIO_REMAPPED;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SRIOV_GET_SET_MSIX_VEC_COUNT, [struct pci_driver has member sriov_get_vf_total_msix/sriov_set_msix_vec_count], [
		#include <linux/pci.h>
	],[
		struct pci_driver core_driver = {
			.sriov_get_vf_total_msix = NULL,
			.sriov_set_msix_vec_count = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BIO_BI_BDEV, [struct bio has member bi_bdev], [
	#include <linux/blk_types.h>
	],[
		struct bio b = {
			.bi_bdev = NULL,
		};
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BDEV_NR_SECTORS, [genhd.h has bdev_nr_sectors], [
		#include <linux/blkdev.h>
	],[
		bdev_nr_sectors(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MQ_BLK_STS_ZONE_ACTIVE_RESOURCE, [blk_types.h has BLK_STS_ZONE_ACTIVE_RESOURCE], [
		#include <linux/blk_types.h>
	],[
		blk_status_t error = BLK_STS_ZONE_ACTIVE_RESOURCE;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DMA_SET_MIN_ALIGN_MASK, [dma_set_min_align_mask is defined in dma-mapping], [
		#include <linux/dma-mapping.h>
	],[
		dma_set_min_align_mask(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BIO_FOR_EACH_BVEC, [bio_for_each_bvec is defined in bio.h], [
		  #include <linux/bio.h>
	],[
		  struct bio *bio;
		  struct bvec_iter bi;
		  struct bio_vec bv;

		  bio_for_each_bvec(bv, bio, bi);

		  return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MQ_HCTX_SET_FQ_LOCK_CLASS, [blk-mq.h has blk_mq_hctx_set_fq_lock_class], [
		#include <linux/blk-mq.h>
	],[
		blk_mq_hctx_set_fq_lock_class(NULL, NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BIO_MAX_VECS, [if bio.h has BIO_MAX_VECS], [
		#include <linux/bio.h>
	],[
		int x = BIO_MAX_VECS;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_RQ_BIO_PREP, [if blk-mq.h has blk_rq_bio_prep], [
		#include <linux/blk-mq.h>
	],[
		blk_rq_bio_prep(NULL, NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_ALLOC_DISK_1_PARAM, [genhd.h has blk_alloc_disk], [
                #include <linux/blkdev.h>
	],[
		blk_alloc_disk(0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PUT_UNALIGNED_LE24_ASM_GENERIC, [put_unaligned_le24 existing in asm-generic/unaligned.h], [
		#include <asm-generic/unaligned.h>
	],[
		put_unaligned_le24(0, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_GENHD_FL_UP, [genhd.h has GENHD_FL_UP], [
		#include <linux/blkdev.h>
	],[
		int x = GENHD_FL_UP;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MQ_ALLOC_DISK_2_PARAMS, [blk_mq_alloc_disk is defined], [
		#include <linux/blk-mq.h>
	],[
		blk_mq_alloc_disk(NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MQ_OPS_POLL_2_ARG, [struct blk_mq_ops has poll 2 args], [
		#include <linux/blk-mq.h>

		static int nvme_poll(struct blk_mq_hw_ctx *hctx,
				     struct io_comp_batch *iob) {
			return 0;
		}
	],[
		struct blk_mq_ops ops = {
			.poll = nvme_poll,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BIO_BI_COOKIE, [struct bio has member bi_cookie], [
		#include <linux/blk_types.h>
	],[
		struct bio b = {
			.bi_cookie = 0,
		};
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVICE_ADD_DISK_RETURN, [genhd.h has device_add_disk retrun], [
		#include <linux/blkdev.h>
	],[
		int ret = device_add_disk(NULL, NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FS_KIOCB_KI_COMPLETE_2_ARG, [linux/fs.h has struct kiocb ki_complete 2 args], [
		#include <linux/fs.h>

		static void func(struct kiocb *iocb, long ret) {
			return;
		}
	],[
		struct kiocb x = {
			.ki_complete = func,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_EXECUTE_RQ_2_PARAM, [blk_execute_rq has 2 params], [
		#include <linux/blk-mq.h>
	],[
		blk_execute_rq(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_GENHD_FL_EXT_DEVT, [genhd.h has GENHD_FL_EXT_DEVT], [
		#include <linux/blkdev.h>
	],[
		int x = GENHD_FL_EXT_DEVT;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_REQ_RQ_DISK, [blkdev.h struct request has rq_disk], [
		#include <linux/blk-mq.h>
	],[
		struct request rq = { .rq_disk = NULL };
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MQ_OPS_QUEUE_RQS, [struct blk_mq_ops has queue_rqs], [
		#include <linux/blk-mq.h>
	],[
		struct blk_mq_ops ops = {
			.queue_rqs = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BDEV_NR_BYTES, [bdev_nr_bytes exist], [
		#include <linux/blkdev.h>
	],[
		bdev_nr_bytes(NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PCI_VENDOR_ID_REDHAT, [PCI_VENDOR_ID_REDHAT is defined], [
		#include <linux/pci_ids.h>
	],[
		int x = PCI_VENDOR_ID_REDHAT;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ACPI_STORAGE_D3, [acpi_storage_d3 exist], [
		#include <linux/acpi.h>
	],[
		acpi_storage_d3(NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PARAM_SET_UINT_MINMAX, [linux/moduleparam.h has param_set_uint_minmax], [
		#include <linux/moduleparam.h>
	],[
		param_set_uint_minmax(NULL, NULL, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_EXPORT_SYMBOL_NS_GPL, [linux/export.h defines EXPORT_SYMBOL_NS_GPL], [
		#include <linux/export.h>
	],[

		#ifdef EXPORT_SYMBOL_NS_GPL
			return 0;
		#else
			#return 1
		#endif

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE___EXPORT_SYMBOL_REF, [linux/export.h defines __EXPORT_SYMBOL_REF], [
		#include <linux/export.h>
	],[

		#ifdef __EXPORT_SYMBOL_REF /* ddb5cdbafaaa, v6.5 and above */
			return 0;
		#else
			#return 1
		#endif

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE___EXPORT_SYMBOL_NS, [linux/export.h defines __EXPORT_SYMBOL_NS], [
		#include <linux/export.h>
	],[

		#ifdef __EXPORT_SYMBOL_NS /* v5.4 only */
			return 0;
		#else
			#return 1
		#endif

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MQ_WAIT_QUIESCE_DONE, [blk_mq_wait_quiesce_done is defined], [
		#include <linux/blk-mq.h>
	],[
		blk_mq_wait_quiesce_done(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MQ_WAIT_QUIESCE_DONE_TAGSET, [blk_mq_wait_quiesce_done with tagset param is defined], [
		#include <linux/blk-mq.h>
	],[
		struct blk_mq_tag_set set = {0};

		blk_mq_wait_quiesce_done(&set);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MQ_OPS_TIMEOUT_1_PARAM, [timeout from struct blk_mq_ops has 1 param], [
		#include <linux/blk-mq.h>
		#include <linux/blkdev.h>

		static enum blk_eh_timer_return
		timeout_dummy(struct request *req) {
			return 0;
		}
	],[
		struct blk_mq_ops ops_dummy;

		ops_dummy.timeout = timeout_dummy;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MQ_DESTROY_QUEUE, [blk_mq_destroy_queue is defined], [
		#include <linux/blk-mq.h>
	],[
		blk_mq_destroy_queue(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_EXECUTE_RQ_3_PARAM, [blk_execute_rq has 3 params], [
		#include <linux/blk-mq.h>
		#include <linux/blkdev.h>
	],[
		blk_status_t x = blk_execute_rq(NULL, NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DISK_UEVENT, [disk_uevent exist], [
		#include <linux/blkdev.h>
	],[
		disk_uevent(NULL, 0);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FC_APPID_LEN, [FC_APPID_LEN is defined], [
		#include <linux/blk-cgroup.h>
	],[
		int x = FC_APPID_LEN;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BVEC_VIRT, [linux/bvec.h has bvec_virt], [
		#include <linux/bio.h>
		#include <linux/bvec.h>
	],[
		bvec_virt(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SOCK_SETOPTVAL_SOCKPTR_T, [net/sock.h has sock_setsockopt sockptr_t], [
		#include <net/sock.h>
	],[
		sockptr_t optval = {};

		sock_setsockopt(NULL, 0, 0, optval, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_NEXT_BIO_3_PARAMS, [bio.h blk_next_bio has 3 parameters], [
		#include <linux/bio.h>
	],[
		blk_next_bio(NULL, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DISK_UPDATE_READAHEAD, [disk_update_readahead exists], [
		#include <linux/blkdev.h>
	],[
		disk_update_readahead(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_VMALLOC_3_PARAM, [linux/vmalloc.h has __vmalloc 3 params], [
		#include <linux/vmalloc.h>
	],[
		__vmalloc(0, 0, PAGE_KERNEL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BIO_INIT_5_PARAMS, [bio.h bio_init has 5 parameters], [
		#include <linux/bio.h>
	],[
		bio_init(NULL, NULL, NULL, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BIO_ADD_ZONE_APPEND_PAGE, [bio.h has bio_add_zone_append_page], [
		#include <linux/bio.h>
	],[
		bio_add_zone_append_page(NULL, NULL, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_CLEANUP_DISK, [blk_cleanup_disk() is defined], [
		#include <linux/blkdev.h>
	],[
		struct gendisk *disk;

		blk_cleanup_disk(disk);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_GENDISK_CONV_ZONES_BITMAP, [struct gendisk has conv_zones_bitmap], [
		#include <linux/blkdev.h>
	],[
		struct gendisk disk;

		disk.conv_zones_bitmap = NULL;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BDEV_NR_ZONES, [blkdev.h has bdev_nr_zones], [
		#include <linux/blkdev.h>
	],[
		bdev_nr_zones(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_QUEUE_ZONE_SECTORS, [blkdev.h has blk_queue_zone_sectors], [
		#include <linux/blkdev.h>
	],[
		blk_queue_zone_sectors(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PTP_PEROUT_DUTY_CYCLE, [PTP_PEROUT_DUTY_CYCLE is defined], [
		#include <uapi/linux/ptp_clock.h>
	],[
		int x = PTP_PEROUT_DUTY_CYCLE;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_STRUCT_MACSEC_INFO_METADATA, [net/dst_metadata.h has struct macsec_info], [
		#include <net/dst_metadata.h>
	],[
		struct macsec_info info = {};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FUNC_MACSEC_GET_REAL_DEV, [net/macsec.c has function macsec_get_real_dev], [
		#include <net/macsec.h>
	],[
		macsec_get_real_dev(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_RX_USES_MD_DST_IN_MACSEC_OPS, [macsec_ops has boolean field rx_uses_md_dst], [
		#include <net/macsec.h>
	],[
		struct macsec_ops ops;
		ops.rx_uses_md_dst = true;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_DISSECTOR_F_STOP_BEFORE_ENCAP, [FLOW_DISSECTOR_F_STOP_BEFORE_ENCAP is defined], [
		#include <net/flow_dissector.h>
	],[
		int x = FLOW_DISSECTOR_F_STOP_BEFORE_ENCAP;

		return 0;
	])

	LB_CHECK_SYMBOL_EXPORT([rpc_task_gfp_mask],
		[net/sunrpc/sched.c],
		[AC_DEFINE(HAVE_RPC_TASK_GPF_MASK_EXPORTED, 1,
			[rpc_task_gfp_mask is exported by the kernel])],
	[])

	MLNX_RDMA_TEST_CASE(HAVE_FUNC_MACSEC_NETDEV_IS_OFFLOADED, [net/macsec.c has function macsec_netdev_is_offloaded], [
		#include <net/macsec.h>
	],[
		macsec_netdev_is_offloaded(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FUNC_MACSEC_NETDEV_PRIV, [net/macsec.h has function macsec_netdev_priv], [
		#include <net/macsec.h>
	],[
		macsec_netdev_priv(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_STRUCT_MACSEC_CONTEXT_UPDATE_PN, [struct macsec_context has update_pn], [
		#include <net/macsec.h>
	],[
		struct macsec_context ctx;
		ctx.sa.update_pn = 0;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FILE_OPERATIONS_URING_CMD, [uring_cmd is defined in file_operations], [
		#include <linux/fs.h>
	],[
		struct file_operations xx = {
			.uring_cmd = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DISK_SET_ZONED, [disk_set_zoned is defined], [
		#include <linux/blkdev.h>
	],[
		disk_set_zoned(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NVME_IOCTL_IO64_CMD_VEC, [NVME_IOCTL_IO64_CMD_VEC is defined], [
		#include <linux/nvme_ioctl.h>
		#include <asm-generic/ioctl.h>
	],[
		unsigned int x = NVME_IOCTL_IO64_CMD_VEC;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_EXT_PI_REF_TAG, [ext_pi_ref_tag is defined], [
		#include <linux/t10-pi.h>
	],[
		ext_pi_ref_tag(NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_OPF_T, [blk_opf_t is defined], [
		#include <linux/blk_types.h>
	],[
		blk_opf_t xx;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FILE_F_IOCB_FLAGS, [sruct file has f_iocb_flags], [
		#include <linux/fs.h>
	],[
		struct file f = {
			.f_iocb_flags = 0,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BDEV_MAX_ZONE_APPEND_SECTORS, [blkdev.h has bdev_max_zone_append_sectors], [
		#include <linux/blkdev.h>
	],[
		bdev_max_zone_append_sectors(NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_RQ_END_IO_RET, [if file rq_end_io_ret exists], [
		#include <linux/blk-mq.h>
	],[
		enum rq_end_io_ret x;
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MQ_OPS_MAP_QUEUES_RETURN_INT, [function map_queues returns int], [
		#include <linux/blk-mq.h>
	],[
		int foo(struct blk_mq_tag_set *x) {
			return 0;
		}

		struct blk_mq_ops ops = {
			.map_queues = foo,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLKCG_GET_FC_APPID, [blkcg_get_fc_appid is defined], [
		#include <linux/blk-cgroup.h>
	],[
		blkcg_get_fc_appid(NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLKDEV_COMPAT_PTR_IOCTL, [blkdev_compat_ptr_ioctl is defined], [
		#include <linux/blkdev.h>
	],[
		blkdev_compat_ptr_ioctl(NULL, 0, 0, 0);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_CHECK_VXLAN_GBP_MASK, [VXLAN_GBP_MASK is defined], [
		#include <net/vxlan.h>
	],[
		uint32_t gbp_mask = VXLAN_GBP_MASK;
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TC_SKB_EXT_ACT_MISS, [linux/skbuff.h struct tc_skb_ext has act-miss], [
		#include <linux/skbuff.h>
	],[
		struct tc_skb_ext ext = {};

		ext.act_miss = 1;
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_CHECK_VXLAN_BUILD_GBP_HDR, [vxlan_build_gbp_hdr is defined], [
		#include <net/vxlan.h>
	],[
		vxlan_build_gbp_hdr(NULL, NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_ACTION_ENTRY_HW_INDEX, [net/flow_offload.h struct flow_action_entry has hw_index], [
		#include <net/flow_offload.h>
	],[
		struct flow_action_entry ent = {};

		ent.hw_index = 0;
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_ACTION_ENTRY_MISS_COOKIE, [net/flow_offload.h struct flow_action_entry has miss_cookie], [
		#include <net/flow_offload.h>
	],[
		struct flow_action_entry ent = {};

		ent.miss_cookie = 0;
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FLOW_ACTION_ENTRY_COOKIE, [net/flow_offload.h struct flow_action_entry has cookie], [
		#include <net/flow_offload.h>
	],[
		struct flow_action_entry ent = {};
		struct flow_offload_action act = {};
		unsigned long cookie = 0;

		ent.cookie = cookie;
		cookie = ent.cookie;

		act.cookie = cookie;
		cookie = act.cookie;

		return cookie ? 1 : 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_USE_ACT_STATS, [flow_cls_offload has use_act_stats], [
		#include <net/flow_offload.h>
	],[
		struct flow_cls_offload cls;

		cls.use_act_stats = true;
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_UAPI_LINUX_NVME_NVME_URING_CMD_ADMIN, [uapi/linux/nvme_ioctl.h has NVME_URING_CMD_ADMIN], [
		#include <linux/nvme_ioctl.h>
		#include <asm-generic/ioctl.h>
	],[
		int x = NVME_URING_CMD_ADMIN;
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MQ_QUEIESCE_TAGSET, [blk_mq_quiesce_tagset is defined], [
		#include <linux/blk-mq.h>
	],[
		blk_mq_quiesce_tagset(NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_RQ_MAP_USER_IO, [blk_rq_map_user_iv is defined], [
		#include <linux/blk-mq.h>
	],[
		blk_rq_map_user_io(NULL, NULL, NULL, 0, 0, 0, 0, 0, 0);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BDEV_START_IO_ACCT, [bdev_start_io_acct is defined], [
		#include <linux/blkdev.h>
	],[
		bdev_start_io_acct(NULL, 0, 0, 0);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BDEV_START_IO_ACCT_3_PARAM, [bdev_start_io_acct is defined], [
		#include <linux/blkdev.h>
	],[
		bdev_start_io_acct(NULL, 0, 0);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FILE_OPERATIONS_URING_CMD_IOPOLL, [uring_cmd_iopoll is defined in file_operations], [
		#include <linux/fs.h>
	],[
		struct file_operations xx = {
			.uring_cmd_iopoll = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NO_LLSEEK, [include/linux/fs.h declares function no_llseek], [
		#include <linux/fs.h>
	],[
		struct file_operations fo = {
			.llseek  = no_llseek,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PR_STATUS, [enum pr_status is defined], [
		#include <linux/fs.h>
		#include <linux/pr.h>
	],[
		enum pr_status x;
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BVEC_SET_VIRT, [bvec_set_virt is defined], [
		#include <linux/bvec.h>
	],[
		bvec_set_virt(NULL, NULL, 0);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DMA_OPT_MAPPING_SIZE, [dma_opt_mapping_size is defined], [
		#include <linux/dma-mapping.h>
	],[
		dma_opt_mapping_size(NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MQ_RQ_STATE, [blk_mq_rq_state is defined], [
		#include <linux/blk-mq.h>
	],[
		blk_mq_rq_state(NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ITER_DEST, [ITER_DEST is defined], [
		#include <linux/uio.h>
	],[
		int x = ITER_DEST;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BVEC_SET_PAGE, [linux/bvec.h has bvec_set_page], [
		#include <linux/bvec.h>
	],[
		bvec_set_page(NULL, NULL, 0, 0);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BDEV_DISCARD_GRANULARITY, [linux/blkdev.h has bdev_discard_granularity], [
		#include <linux/blkdev.h>
	],[
		bdev_discard_granularity(NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_KSTRTOX_H, [kstrtox.h exist], [
		#include <linux/kstrtox.h>
	],[
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DIM_CQ_PERIOD_MODE, [include/linux/dim.h defines enum dim_cq_period_mode], [
		#include <linux/dim.h>
	],[
		enum dim_cq_period_mode dcpm = DIM_CQ_PERIOD_MODE_START_FROM_EQE;
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BDEV_WRITE_CACHE, [linux/blkdev.h has bdev_write_cache], [
		#include <linux/blkdev.h>
	],[
		bdev_write_cache(NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TRACE_EVENTS_TRACE_SK_DATA_READY, [trace/events/sock.h has trace_sk_data_ready], [
		#include <trace/events/sock.h>
	],[
		trace_sk_data_ready(NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TRY_CMPXCHG, [linux/atomic/atomic-instrumented.h has try_cmpxchg], [
		#include <linux/mm_types.h>
		#include <linux/atomic/atomic-instrumented.h>
	],[
			u32 x = 0;
			try_cmpxchg(&x, &x, x);
			return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_ZONE_NO, [linux/blkdev.h has bdev_zone_no], [
		#include <linux/blkdev.h>
	],[
			bdev_zone_no(NULL, 0);
			return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BIO_START_IO_ACCT, [bdev_start_io_acct is defined], [
		#include <linux/blkdev.h>
	],[
		bdev_start_io_acct(NULL, 0, 0, 0);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BDEV_IS_PARTITION, [bdev_is_partition is defined], [
		#include <linux/blkdev.h>
	],[
		bdev_is_partition(NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_GENDISK_OPEN_MODE, [struct gendisk has open_mode], [
		#include <linux/blkdev.h>
	],[
		struct gendisk disk;

		disk.open_mode = BLK_OPEN_READ;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_STS_RESV_CONFLICT, [blk_types.h has BLK_STS_RESV_CONFLICT], [
		#include <linux/blk_types.h>
	],[
		blk_status_t error = BLK_STS_RESV_CONFLICT;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLKDEV_PUT_HOLDER, [blkdev_put has holder param], [
		#include <linux/blkdev.h>
	],[
		blkdev_put(NULL, NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PROTO_OPS_SENDPAGE, [net.h struct proto_ops has sendpage], [
		#include <linux/net.h>
	],[
		struct proto_ops x = {
			.sendpage = NULL,
		};
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MQ_TAG_SET_HAS_NR_MAP, [blk_mq_tag_set has member nr_maps], [
		#include <linux/blk-mq.h>
	],[
		struct blk_mq_tag_set x = {
			.nr_maps = 0,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MQ_HCTX_TYPE, [blk-mq.h has enum hctx_type], [
		#include <linux/blk-mq.h>
	],[
		enum hctx_type type = HCTX_TYPE_DEFAULT;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_IRQ_AFFINITY_PRIV, [struct irq_affinity has priv], [
		#include <linux/interrupt.h>
	],[
		struct irq_affinity affd = {
			.priv = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PCI_ENABLE_PCIE_ERROR_REPORTING, [linux/aer.h has pci_enable_pcie_error_reporting], [
		#include <linux/aer.h>
	],[
		pci_enable_pcie_error_reporting(NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MQ_TAG_SET_HAS_MAP, [blk_mq_tag_set has member map], [
		#include <linux/blk-mq.h>
	],[
		struct blk_mq_tag_set x = {
			.map = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_QUEUE_FLAG_PCI_P2PDMA, [QUEUE_FLAG_PCI_P2PDMA is defined], [
		#include <linux/blkdev.h>
	],[
		int x = QUEUE_FLAG_PCI_P2PDMA;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_REQUEST_HAS_DEADLINE, [blkdev.h struct request has deadline], [
		#include <linux/blkdev.h>
		#include <linux/blk-mq.h>
	],[
		struct request rq = { .deadline = 0 };
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MQ_OPS_COMMIT_RQS, [struct blk_mq_ops has commit_rqs], [
		#include <linux/blk-mq.h>
	],[
		struct blk_mq_ops ops = {
			.commit_rqs = NULL,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_STRUCT_SIZE_T, [linux/overflow.h has struct_size_t], [
		#include <linux/overflow.h>
	],[
		struct test {
			int arr[[0]];
		};

		size_t x = struct_size_t(struct test, arr, 1);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PR_KEYS, [linux/pr.h has struct pr_keys], [
		#include <linux/fs.h>
		#include <linux/pr.h>
	],[
		struct pr_keys x;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DMA_MAX_MAPPING_SIZE, [linux/dma-mapping.h has dma_max_mapping_size], [
		#include <linux/dma-mapping.h>
	],[
		dma_max_mapping_size(NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DMA_ATTR_WRITE_BARRIER, [linux/dma-mapping.h defines macro DMA_ATTR_WRITE_BARRIER], [
		#include <linux/dma-mapping.h>
	],[
		#ifdef DMA_ATTR_WRITE_BARRIER
			return 0;
		#else
			#return 1
		#endif

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SCSI_TRANSPORT_FC_FC_PORT_ROLE_NVME_TARGET, [scsi/scsi_transport_fc.h has FC_PORT_ROLE_NVME_TARGET], [
		#include <scsi/scsi_transport_fc.h>
	],[
		int x = FC_PORT_ROLE_NVME_TARGET;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_IO_URING_CMD_H, [linux/io_uring/cmd.h exists], [
		#include <linux/io_uring/cmd.h>
	],[
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_HWMON_CHIP_INFO_CONST_INFO, [hwmon_chip_info get const nvme_hwmon_ops], [
		#include <linux/hwmon.h>
	],[
		static const struct hwmon_channel_info *const nvme_hwmon_info[[]] = { 0 };
		static const struct hwmon_chip_info nvme_hwmon_chip_info = {
			.info	= nvme_hwmon_info,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NVME_AUTH_TRANSFORM_KEY_DHCHAP, [nvme_auth_transform_key returns struct nvme_dhchap_key *], [
		#include <linux/nvme-auth.h>
	],[
		struct nvme_dhchap_key *x = nvme_auth_transform_key(NULL, NULL);
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BIO_INTEGRITY_MAP_USER_BIO_H, [bio.h has bio_integrity_map_user], [
		#include <linux/bio.h>
	],[
		bio_integrity_map_user(NULL, NULL, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PCIE_CAPABILITY_CLEAR_AND_SET_WORD_LOCKED, [pci.h has pcie_capability_clear_and_set_word_locked], [
		#include <linux/pci.h>
	],[
		pcie_capability_clear_and_set_word_locked(NULL, 0, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PCI_ENABLE_PTM, [include/linux/pci.h has pci_enable_ptm], [
		#include <linux/pci.h>
	],[
		pci_enable_ptm(NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PCI_DISABLE_PTM, [include/linux/pci.h has pci_disable_ptm], [
		#include <linux/pci.h>
	],[
		pci_disable_ptm(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_TYPES_PAGE_SECTORS_SHIFT, [PAGE_SECTORS_SHIFT is defined], [
		#include <linux/blk_types.h>
	],[
		int x = PAGE_SECTORS_SHIFT;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BDEV_RELEASE, [bdev_release has holder param], [
		#include <linux/blkdev.h>
	],[
		bdev_release(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_IN_COMPAT_SYSCALL, [linux/compat.h has in_compat_syscall], [
		#include <linux/compat.h>
	],[
		in_compat_syscall();

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_ALLOC_QUEUE_NODE_3_ARGS, [blk_alloc_queue_node has 3 args], [
		#include <linux/blkdev.h>
	],[
		blk_alloc_queue_node(0, 0, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_REQUEST_MQ_HCTX, [blkdev.h struct request has mq_hctx], [
		#include <linux/blkdev.h>
		#include <linux/blk-mq.h>
	],[
		struct request rq = { .mq_hctx = NULL };
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MQ_QUEUE_MAP, [linux/blk-mq.h has struct blk_mq_queue_map], [
		#include <linux/blk-mq.h>
	],[
		struct blk_mq_queue_map x = {};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_HOLDER_OPS, [linux/blk-mq.h has struct blk_holder_ops], [
		#include <linux/blkdev.h>
	],[
		struct blk_holder_ops x = {};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SK_USE_TASK_FRAG, [struct sock has sk_use_task_frag], [
		#include <net/sock.h>
	],[
		struct sock sk = { .sk_use_task_frag = false };
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_ALLOC_DISK_2_PARAMS, [genhd.h has blk_alloc_disk], [
                #include <linux/blkdev.h>
	],[
		blk_alloc_disk(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_QUEUE_LIMITS_COMMIT_UPDATE, [blkdev.h has queue_limits_commit_update], [
                #include <linux/blkdev.h>
	],[
		queue_limits_commit_update(NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_INTEGRITY_PI_OFFSET, [struct blk_integrity has pi_offset], [
		#include <linux/blkdev.h>
	],[
		struct blk_integrity s = { .pi_offset = 42 };
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MQ_ALLOC_DISK_3_PARAMS, [blk_mq_alloc_disk has 3 param], [
		#include <linux/blk-mq.h>
	],[
		blk_mq_alloc_disk(NULL, NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MQ_ALLOC_QUEUE, [blk_mq_alloc_queue is defined], [
		#include <linux/blk-mq.h>
	],[
		blk_mq_alloc_queue(NULL, NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BDEV_FILE_OPEN_BY_PATH, [linux/blkdev.h has bdev_file_open_by_path], [
		#include <linux/blkdev.h>
	],[
		bdev_file_open_by_path(NULL, 0, NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PAGE_FRAG_CACHE_DRAIN_IN_GFP_H, [linux/gfp.h has page_frag_cache_drain], [
		#include <linux/gfp.h>
	],[
		page_frag_cache_drain(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ALLOC_BULK_PAGES_API_RENAME, [linux/gfp.h has v6.14 alloc_bulk_pages API rename], [
		#include <linux/mm_types.h>
		#include <linux/gfp.h>
	],[
		unsigned int to_fill = 1;
		struct page **page_list;

		alloc_pages_bulk(GFP_KERNEL_ACCOUNT, to_fill, page_list);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PAGE_FRAG_CACHE_DRAIN_IN_PAGE_FRAG_CACHE_H, [linux/page_frag_cache.h has page_frag_cache_drain], [
		#include <linux/page_frag_cache.h>
	],[
		page_frag_cache_drain(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLKDEV_ZONE_MGMT_5_PARAMS, [linux/blkdev.h has blkdev_zone_mgmt with 5 params], [
		#include <linux/blkdev.h>
	],[
		int ret = blkdev_zone_mgmt(NULL, 0, 0, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_RATELIMIT_TYPES_H, [linux/ratelimit_types.h exists], [
		#include <linux/ratelimit_types.h>
	],[
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_OP_STR, [linux/blkdev.h has blk_op_str], [
		#include <linux/blkdev.h>
	],[
		const char *s = blk_op_str(0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_REQUEST_QUEUE_DISK, [if linux/blkdev.h struct request_queue has member disk], [
		#include <linux/blkdev.h>
	],[
		struct request_queue q = { .disk = NULL};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_QUEUE_FLAG_DISCARD, [QUEUE_FLAG_DISCARD is defined], [
		#include <linux/blkdev.h>
	],[
		int x = QUEUE_FLAG_DISCARD;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DEVLINK_PORT_MAX_IO_EQS, [struct devlink_port_ops has max_io_eqs], [
	#include <net/devlink.h>
	],[
		struct devlink_port_ops ops;

		ops.port_fn_max_io_eqs_get = NULL;
		ops.port_fn_max_io_eqs_set = NULL;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_RQF_MQ_INFLIGHT, [RQF_MQ_INFLIGHT is defined], [
		#include <linux/blk-mq.h>
		#include <linux/blkdev.h>
	],[
		int x = RQF_MQ_INFLIGHT;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MQ_MAP_HW_QUEUES, [Kernel provides v6.14 blk_mq_map_hw_queues], [
		#include <linux/blk-mq.h>
	],[
		blk_mq_map_hw_queues(NULL, NULL, 5);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FORCE_NOIO_SCOPE_IN_BLK_MQ_FREEZE_QUEUE, [Kernel has v6.14 'force noio scope in blk_mq_freeze_queue'], [
		#include <linux/blk-mq.h>
	],[
		int x;

		x = blk_mq_freeze_queue(NULL);
		blk_mq_unfreeze_queue(NULL, 1);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NON_OWNER_VARIANT_OF_START_FREEZE_QUEUE, [Kernel has v6.13 'add non_owner variant of start_freeze/unfreeze queue APIs'], [
		#include <linux/blk-mq.h>
	],[
		blk_freeze_queue_start_non_owner(NULL);
		blk_mq_unfreeze_queue_non_owner(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MQ_F_NO_SCHED, [linux/blk-mq.h provides BLK_MQ_F_NO_SCHED which was removed in 6.14-rc1], [
		#include <linux/blk-mq.h>
	],[
		int x = BLK_MQ_F_NO_SCHED;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_MQ_F_SHOULD_MERGE, [linux/blk-mq.h provides BLK_MQ_F_SHOULD_MERGE which was removed in 6.14-rc1], [
		#include <linux/blk-mq.h>
	],[
		int x = BLK_MQ_F_SHOULD_MERGE;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_INTEGRITY_CSUM_CRC64, [BLK_INTEGRITY_CSUM_CRC64 is defined], [
		#include <linux/blkdev.h>
	],[
		enum blk_integrity_checksum bic = BLK_INTEGRITY_CSUM_CRC64;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_INTEGRITY_H, [include/linux/blk-integrity.h exists], [
		#include <linux/blk-integrity.h>
	],[
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_RQ_INTEGRITY_MAP_USER_GET_4_PARAM, [blk_rq_integrity_map_user exists], [
		#include <linux/blk-integrity.h>
	],[
		int ret = blk_rq_integrity_map_user(NULL, NULL, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_RQ_INTEGRITY_MAP_USER_GET_3_PARAM, [blk_rq_integrity_map_user exists], [
		#include <linux/blk-integrity.h>
	],[
		int ret = blk_rq_integrity_map_user(NULL, NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_RQ_MAP_INTEGRITY_SG_GET_2_PARAMS, [blk_rq_map_integrity_sg get 2 params], [
		#include <linux/blk-integrity.h>
	],[
		int ret = blk_rq_map_integrity_sg(NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BIO_INTEGRITY_H, [include/linux/bio-integrity.h exists], [
		#include <linux/bio-integrity.h>
	],[
		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_RQ_INTEGRITY_RETURN_BIO_VEC, [rq_integrity_vec returns struct bio_vec], [
		#include <linux/blk-integrity.h>
	],[
		struct bio_vec bvec = rq_integrity_vec(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_REVALIDATE_DISK_ZONES_1_PARAM, [blk_revalidate_disk_zones get 1 param], [
		#include <linux/blkdev.h>
	],[
		int ret = blk_revalidate_disk_zones(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_QUEUE_ATOMIC_WRITE_BOUNDARY_BYTES, [queue_atomic_write_boundary_bytes exists], [
		#include <linux/blkdev.h>
	],[
		unsigned int ret = queue_atomic_write_boundary_bytes(NULL);
		struct queue_limits lim = { .atomic_write_hw_boundary = 0};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ENUM_BLK_UNIQUE_ID, [enum blk_unique_id is defined], [
		#include <linux/blkdev.h>
	],[
		enum blk_unique_id buid = BLK_UID_EUI64;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PLATFORM_DEVICE_REMOVE_NEW, [struct platform_driver has remove_new], [
		#include <linux/platform_device.h>

		static void apple_nvme_remove(struct platform_device *pdev) {}
	],[
		struct platform_driver apple_nvme_driver = {
			.remove_new = apple_nvme_remove,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SENDPAGES_OK, [linux/net.h has sendpages_ok], [
		#include <linux/net.h>
	],[
		sendpages_ok(NULL, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_IO_URING_CMD_IOPOLL_DONE, [linux/io_uring/cmd.h has io_uring_cmd_iopoll_done], [
		#include <linux/io_uring/cmd.h>
	],[
		io_uring_cmd_iopoll_done(NULL, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_FEAT_ZONED, [BLK_FEAT_ZONED is defined], [
		#include <linux/blkdev.h>
	],[
		int x = BLK_FEAT_ZONED;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_GD_SUPPRESS_PART_SCAN, [GD_SUPPRESS_PART_SCAN is defined], [
		#include <linux/blkdev.h>
	],[
		int x = GD_SUPPRESS_PART_SCAN;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SBITMAP_GET_1_PARAM, [linux/sbitmap.h has sbitmap_get with 1 param], [
		#include <linux/sbitmap.h>
	],[
		sbitmap_get(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SBITMAP_GET_2_PARAMS, [linux/sbitmap.h has sbitmap_get with 2 params], [
		#include <linux/sbitmap.h>
	],[
		sbitmap_get(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_COMPAT_UPTR_T, [linux/compat.h has compat_uptr_t], [
		#include <linux/compat.h>
	],[
		compat_uptr_t x;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_STD_GNU_99, [kernel is build with -std=gnu99], [
		#include <linux/compat.h>
	],[
		for (int i = 0; i < 10; i++)
			;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_STRUCT_RQ_LIST, [linux/blkdev.h has struct rq_list], [
		#include <linux/blkdev.h>
	],[
		struct rq_list x;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_WRITE_BEGIN_FOLIO, [if address_space_operations->write_begin takes a folio param], [
		#include <linux/fs.h>
	],[
		struct folio *f;
		struct address_space_operations ops = {0};
		ops.write_begin(NULL, NULL, 0, 0, &f, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_GRAB_CACHE_PAGE_WRITE_BEGIN, [if grab_cache_page_write_begin() exists], [
		#include <linux/fs.h>
	],[
		grab_cache_page_write_begin(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_MKDIR_RET_DENTRY, [if struct inode_operations->mkdir returns a dentry], [
		#include <linux/fs.h>

		static struct dentry *my_mkdir(struct mnt_idmap *idmap, struct inode *dir, struct dentry *entry, umode_t mode)
		{return 0;}
	],[
		struct inode_operations ops = {.mkdir = my_mkdir};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_D_REVALIDATE_2_PARAMS, [if dentry_operations->d_revalidate takes 2 params], [
		#include <linux/dcache.h>
	],[
		struct dentry_operations ops = {0};

		ops.d_revalidate(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SECURITY_DENTRY_INIT_SECURITY_6_PARAMS, [if security_dentry_init_security() takes 6 params], [
		#include <linux/security.h>
	],[
		security_dentry_init_security(NULL, 0, NULL, NULL, NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FILE_LOCK_CORE_C, [if struct file_lock has c field], [
		#include <linux/filelock.h>
	],[
		struct file_lock a;
		struct file_lock_core b;

		b = a.c;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FUSE_NO_EXPORT_SUPPORT, [if FUSE_NO_EXPORT_SUPPORT is defined], [
		#include <uapi/linux/fuse.h>
	],[
		long long unsigned int a = FUSE_NO_EXPORT_SUPPORT;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_VIRTQUEUE_INFO, [if struct virtqueue_info is defined], [
		#include <linux/virtio_config.h>
	],[
		struct virtqueue_info vqi;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_IN_GROUP_OR_CAPABLE, [if func in_group_or_capable is defined], [
		#include <linux/fs.h>
	],[
		vfsgid_t gid = {0};

		in_group_or_capable(NULL, NULL, gid);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FUSE_HAS_RESEND, [if FUSE_HAS_RESEND is defined], [
		#include <uapi/linux/fuse.h>
	],[
		long long unsigned int a = FUSE_HAS_RESEND;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FUSE_NOTIFY_RESEND, [if FUSE_NOTIFY_RESEND is defined], [
		#include <uapi/linux/fuse.h>
	],[
		long long unsigned int a = FUSE_NOTIFY_RESEND;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FUSE_PASSTHROUGH, [if FUSE_PASSTHROUGH is defined], [
		#include <uapi/linux/fuse.h>
	],[
		long long unsigned int a = FUSE_PASSTHROUGH;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TLS_CIPHER_AES_GCM_256, [include/uapi/linux/tls.h defines TLS_CIPHER_AES_GCM_256], [
		#include <uapi/linux/tls.h>
	],[
		#ifdef TLS_CIPHER_AES_GCM_256
			return 0;
		#else
			#return 1
		#endif

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BIO_ADD_PC_PAGE, [if bio_add_pc_page is defined], [
		#include <linux/bio.h>
	],[
		bio_add_pc_page(NULL, NULL, NULL, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PLATFORM_DEVICE_REMOVE_NO_RET, [struct platform_driver has remove with no ret], [
		#include <linux/platform_device.h>

		static void apple_nvme_remove(struct platform_device *pdev) {}
	],[
		struct platform_driver apple_nvme_driver = {
			.remove = apple_nvme_remove,
		};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_ITER_ALLOW_P2PDMA, [uio.h has ITER_ALLOW_P2PDMA], [
		#include <linux/uio.h>
	],[
		iov_iter_extraction_t f = ITER_ALLOW_P2PDMA;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_U64_STATS_T, [type u64_stats_t exists], [
		#include <linux/u64_stats_sync.h>
	],[
		u64_stats_t x;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BIO_INTEGRITY_PAYLOAD_APP_TAG, [struct bio_integrity_payload has member app_tag], [
		#include <linux/bio-integrity.h>
	],[
		struct bio_integrity_payload s = {.app_tag = 0};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SECS_TO_JIFFIES, [jiffies.h has secs_to_jiffies], [
		#include <linux/jiffies.h>
	],[
		unsigned long x = secs_to_jiffies(1);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_RQ_MAP_SG_2_PARAMS, [blk-mq.h has blk_rq_map_sg with 2 params], [
		 #include <linux/blk-mq.h>
	],[
		blk_rq_map_sg(NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_RQ_MAP_KERN_4_PARAMS, [blk_rq_map_kern has 4 params without queue], [
		#include <linux/blk-mq.h>
	],[
		blk_rq_map_kern(NULL, NULL, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PCI_DEV_IS_DISCONNECTED, [pci.h has pci_dev_is_disconnect], [
		#include <linux/pci.h>
	],[
		bool x = pci_dev_is_disconnected(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_STR_PLURAL, [string_choices.h has str_plural], [
		#include <linux/string_choices.h>
	],[
		const char *s = str_plural(42);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BDEV_NONROT, [blkdev.h has bdev_nonrot], [
		#include <linux/blkdev.h>
	],[
		bool x = bdev_nonrot(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_REQUEST_QUEUE_IA_RANGES, [blkdev.h struct request_queue has ia_ranges], [
		#include <linux/blkdev.h>
	],[
		struct request_queue rq = {.ia_ranges = NULL};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_GENDISK_IA_RANGES, [blkdev.h struct gendisk has ia_ranges], [
		#include <linux/blkdev.h>
	],[
		struct gendisk gd = {.ia_ranges = NULL};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BDEV_BD_STATS, [struct block_device has bd_stats], [
		#include <linux/blk_types.h>
	],[
		struct block_device bdev = {.bd_stats = NULL};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PERCPU_REF_RESURRECT, [percpu-refcount.h has percpu_ref_resurrect], [
		#include <linux/percpu-refcount.h>
	],[
		percpu_ref_resurrect(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PERCPU_REF_ALLOW_REINIT, [percpu-refcount.h has PERCPU_REF_ALLOW_REINIT], [
		#include <linux/percpu-refcount.h>
	],[
		int x = PERCPU_REF_ALLOW_REINIT;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_TIMER_DELETE_SYNC, [timer.h has timer_delete_sync], [
		#include <linux/timer.h>
	],[
		timer_delete_sync(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_DMA_ALLOC_NONCONTIGUOUS, [dma_alloc_noncontiguous is defined], [
		#include <linux/dma-mapping.h>
	],[
		dma_alloc_noncontiguous(NULL, 0, 0, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_MEMREMAP_COMPAT_ALIGN, [memremap_compat_align is defined], [
		#include <linux/memremap.h>
	],[
		unsigned long x = memremap_compat_align();

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SYSFS_GROUP_INVISIBLE, [SYSFS_GROUP_INVISIBLE is defined], [
		#include <linux/sysfs.h>
	],[

		int x = SYSFS_GROUP_INVISIBLE;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_IO_URING_CMD_TO_PDU, [io_uring_cmd_to_pdu is defined], [
		#include <linux/io_uring/cmd.h>
	],[
		#ifndef io_uring_cmd_to_pdu
		#error undefined
		#endif
	])

	MLNX_RDMA_TEST_CASE(HAVE_IO_URING_CMD_IMPORT_FIXED_6_PARAMS, [io_uring_cmd_import_fixed has 6 params], [
		#include <linux/io_uring/cmd.h>
	],[
		int r = io_uring_cmd_import_fixed(0, 0, 0, NULL, NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_GD_ADDED, [GD_ADDED is defined], [
		#include <linux/blkdev.h>
	],[
		int x = GD_ADDED;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NVME_TCP_MIN_C2HTERM_PLEN, [NVME_TCP_MIN_C2HTERM_PLEN is defined], [
		#include <linux/nvme-tcp.h>
	],[
		int x = NVME_TCP_MIN_C2HTERM_PLEN;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SK_NET_REFCNT_UPGRADE, [sk_net_refcnt_upgrade is defined], [
		#include <net/sock.h>
	],[
		sk_net_refcnt_upgrade(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_FEAT_ATOMIC_WRITES, [BLK_FEAT_ATOMIC_WRITES is defined], [
		#include <linux/blkdev.h>
	],[
		unsigned long x = (unsigned long)BLK_FEAT_ATOMIC_WRITES;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NVME_AUTH_GENERATE_PSK, [nvme_auth_generate_psk is defined], [
		#include <linux/nvme-auth.h>
	],[
		u8 *b;
		int x = nvme_auth_generate_psk(0, NULL, 0, NULL, NULL, 0, &b, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_BLK_FEAT_ROTATIONAL, [BLK_FEAT_ROTATIONAL is defined], [
		#include <linux/blkdev.h>
	],[
		int x = BLK_FEAT_ROTATIONAL;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NVME_AUTH_GENERATE_DIGEST, [nvme_auth_generate_digest is defined], [
		#include <linux/nvme-auth.h>
	],[
		u8 *b;
		int x = nvme_auth_generate_digest(0, NULL, 0, NULL, NULL, &b);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_NVME_AUTH_DERIVE_TLS_PSK, [nvme_auth_derive_tls_psk is defined], [
		#include <linux/nvme-auth.h>
	],[
		u8 *b;
		int x = nvme_auth_derive_tls_psk(0, NULL, 0, NULL, &b);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_APPLE_RTKIT_OPS_CRASHED_3_PARAMS, [apple_rtkit_ops.crashed takes 3 params], [
		#include <linux/soc/apple/rtkit.h>
		void foo(void *cookie, const void *crashlog, size_t crashlog_size);
	],[
		struct apple_rtkit_ops ops = {.crashed = foo};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PCI_EPC_FEATURES_INTX_CAPABLE, [desc], [
		#include <linux/pci-epc.h>
	],[
		struct pci_epc_features s = {.intx_capable = 1};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_VIRTIO_DEVICE_RESET_PREPARE, [virtio_device_reset_prepare is defined], [
		#include <linux/virtio.h>
	],[
		virtio_device_reset_prepare(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FOLIO_INDEX, [folio_index() is defined], [
		#include <linux/pagemap.h>
	],[
		pgoff_t r = folio_index(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_INVALID_MNT_IDMAP, [invalid_mnt_idmap is defined], [
		#include <linux/mnt_idmapping.h>
	],[
		struct mnt_idmap *p = &invalid_mnt_idmap;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SB_I_NOIDMAP, [SB_I_NOIDMAP is defined], [
		#include <uapi/linux/fuse.h>
	],[
		unsigned long x = SB_I_NOIDMAP;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_STRUCT_LSMCONTEXT, [struct lsmcontext is defined], [
		#include <linux/security.h>
	],[
		/* On Ubuntu 'struct lsm_context' is named 'struct lsmcontext' for some reason... */
		struct lsmcontext x = {};

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_PAGE_GET_LINK_RAW, [page_get_link_raw is defined], [
		#include <linux/fs.h>
	],[
		const char *s = page_get_link_raw(NULL, NULL, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FOLIO_MARK_DIRTY_LOCK, [folio_mark_dirty_lock is defined], [
		#include <linux/mm.h>
	],[
		folio_mark_dirty_lock(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_COPY_FOLIO_FROM_ITER, [copy_folio_from_iter is defined], [
		#include <linux/uio.h>
	],[
		size_t r = copy_folio_from_iter(NULL, 0, 0, NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_UNPIN_FOLIO, [unpin_folio is defined], [
		#include <linux/mm.h>
	],[
		unpin_folio(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_INODE_GET_MTIME, [inode_get_mtime is defined], [
		#include <linux/fs.h>
	],[
		inode_get_mtime(NULL);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FILEID_INO64, [FILEID_INO64_GEN is defined], [
		#include <linux/exportfs.h>
	],[
		int x = FILEID_INO64_GEN;

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_FOLIO_END_READ, [folio_end_read is defined], [
		#include <linux/pagemap.h>
	],[
		folio_end_read(NULL, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_SPLICE_COPY_FILE_RANGE, [splice_copy_file_range is defined], [
		#include <linux/splice.h>
	],[
		splice_copy_file_range(NULL, 0, NULL, 0, 0);

		return 0;
	])

	MLNX_RDMA_TEST_CASE(HAVE_CONST_XATTR_HANDLER, [sb->s_xattr point is double-const], [
		#include <linux/fs.h>
	],[
		struct super_block sb;
		const struct xattr_handler * const ops;

		sb.s_xattr = &ops;

		return 0;
	])

	LB_CHECK_SYMBOL_EXPORT([folio_copy],
		[mm/util.c],
		[AC_DEFINE(HAVE_FOLIO_COPY_EXPORTED, 1,
			[folio_copy is exported by the kernel])],
	[])

	MLNX_RDMA_TEST_CASE(HAVE_DEV_NET_RCU, [function dev_net_rcu is defined], [
		#include <linux/netdevice.h>
	],[
		struct net *p = dev_net_rcu(NULL);

		return 0;
	])
])

AC_DEFUN([LINUX_CONFIG_COMPAT],
[
MLNX_RDMA_SET_GLOBALS
MLNX_RDMA_CREATE_MODULES
MLNX_RDMA_BUILD_MODULES
MLNX_RDMA_CHECK_RESULTS
])

#
# COMPAT_CONFIG_HEADERS
#
# add -include config.h
#
AC_DEFUN([COMPAT_CONFIG_HEADERS],[
#
#	Generate the config.h header file
#
	AC_CONFIG_HEADERS([config.h])
	EXTRA_KCFLAGS="-include $PWD/config.h $EXTRA_KCFLAGS"
	AC_SUBST(EXTRA_KCFLAGS)
])

AC_DEFUN([MLNX_PROG_LINUX],
[
LB_LINUX_PATH
LB_IS_LLVM
LB_LINUX_SYMVERFILE

LINUX_CONFIG_COMPAT
COMPAT_CONFIG_HEADERS

])

