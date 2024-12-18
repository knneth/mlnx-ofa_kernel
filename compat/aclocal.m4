# generated automatically by aclocal 1.15 -*- Autoconf -*-

# Copyright (C) 1996-2014 Free Software Foundation, Inc.

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
m4_if(m4_defn([AC_AUTOCONF_VERSION]), [2.69],,
[m4_warning([this file was generated for autoconf 2.69.
You have another version of autoconf.  It may work, but is not guaranteed to.
If you have problems, you may need to regenerate the build system entirely.
To do so, use the procedure documented by the package, typically 'autoreconf'.])])

# Copyright (C) 2002-2014 Free Software Foundation, Inc.
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
[am__api_version='1.15'
dnl Some users find AM_AUTOMAKE_VERSION and mistake it for a way to
dnl require some minimum version.  Point them to the right macro.
m4_if([$1], [1.15], [],
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
[AM_AUTOMAKE_VERSION([1.15])dnl
m4_ifndef([AC_AUTOCONF_VERSION],
  [m4_copy([m4_PACKAGE_VERSION], [AC_AUTOCONF_VERSION])])dnl
_AM_AUTOCONF_VERSION(m4_defn([AC_AUTOCONF_VERSION]))])

# Figure out how to run the assembler.                      -*- Autoconf -*-

# Copyright (C) 2001-2014 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# AM_PROG_AS
# ----------
AC_DEFUN([AM_PROG_AS],
[# By default we simply use the C compiler to build assembly code.
AC_REQUIRE([AC_PROG_CC])
test "${CCAS+set}" = set || CCAS=$CC
test "${CCASFLAGS+set}" = set || CCASFLAGS=$CFLAGS
AC_ARG_VAR([CCAS],      [assembler compiler command (defaults to CC)])
AC_ARG_VAR([CCASFLAGS], [assembler compiler flags (defaults to CFLAGS)])
_AM_IF_OPTION([no-dependencies],, [_AM_DEPENDENCIES([CCAS])])dnl
])

# AM_AUX_DIR_EXPAND                                         -*- Autoconf -*-

# Copyright (C) 2001-2014 Free Software Foundation, Inc.
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

# AM_CONDITIONAL                                            -*- Autoconf -*-

# Copyright (C) 1997-2014 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# AM_CONDITIONAL(NAME, SHELL-CONDITION)
# -------------------------------------
# Define a conditional.
AC_DEFUN([AM_CONDITIONAL],
[AC_PREREQ([2.52])dnl
 m4_if([$1], [TRUE],  [AC_FATAL([$0: invalid condition: $1])],
       [$1], [FALSE], [AC_FATAL([$0: invalid condition: $1])])dnl
AC_SUBST([$1_TRUE])dnl
AC_SUBST([$1_FALSE])dnl
_AM_SUBST_NOTMAKE([$1_TRUE])dnl
_AM_SUBST_NOTMAKE([$1_FALSE])dnl
m4_define([_AM_COND_VALUE_$1], [$2])dnl
if $2; then
  $1_TRUE=
  $1_FALSE='#'
else
  $1_TRUE='#'
  $1_FALSE=
fi
AC_CONFIG_COMMANDS_PRE(
[if test -z "${$1_TRUE}" && test -z "${$1_FALSE}"; then
  AC_MSG_ERROR([[conditional "$1" was never defined.
Usually this means the macro was only invoked conditionally.]])
fi])])

# Copyright (C) 1999-2014 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.


# There are a few dirty hacks below to avoid letting 'AC_PROG_CC' be
# written in clear, in which case automake, when reading aclocal.m4,
# will think it sees a *use*, and therefore will trigger all it's
# C support machinery.  Also note that it means that autoscan, seeing
# CC etc. in the Makefile, will ask for an AC_PROG_CC use...


# _AM_DEPENDENCIES(NAME)
# ----------------------
# See how the compiler implements dependency checking.
# NAME is "CC", "CXX", "OBJC", "OBJCXX", "UPC", or "GJC".
# We try a few techniques and use that to set a single cache variable.
#
# We don't AC_REQUIRE the corresponding AC_PROG_CC since the latter was
# modified to invoke _AM_DEPENDENCIES(CC); we would have a circular
# dependency, and given that the user is not expected to run this macro,
# just rely on AC_PROG_CC.
AC_DEFUN([_AM_DEPENDENCIES],
[AC_REQUIRE([AM_SET_DEPDIR])dnl
AC_REQUIRE([AM_OUTPUT_DEPENDENCY_COMMANDS])dnl
AC_REQUIRE([AM_MAKE_INCLUDE])dnl
AC_REQUIRE([AM_DEP_TRACK])dnl

m4_if([$1], [CC],   [depcc="$CC"   am_compiler_list=],
      [$1], [CXX],  [depcc="$CXX"  am_compiler_list=],
      [$1], [OBJC], [depcc="$OBJC" am_compiler_list='gcc3 gcc'],
      [$1], [OBJCXX], [depcc="$OBJCXX" am_compiler_list='gcc3 gcc'],
      [$1], [UPC],  [depcc="$UPC"  am_compiler_list=],
      [$1], [GCJ],  [depcc="$GCJ"  am_compiler_list='gcc3 gcc'],
                    [depcc="$$1"   am_compiler_list=])

AC_CACHE_CHECK([dependency style of $depcc],
               [am_cv_$1_dependencies_compiler_type],
[if test -z "$AMDEP_TRUE" && test -f "$am_depcomp"; then
  # We make a subdir and do the tests there.  Otherwise we can end up
  # making bogus files that we don't know about and never remove.  For
  # instance it was reported that on HP-UX the gcc test will end up
  # making a dummy file named 'D' -- because '-MD' means "put the output
  # in D".
  rm -rf conftest.dir
  mkdir conftest.dir
  # Copy depcomp to subdir because otherwise we won't find it if we're
  # using a relative directory.
  cp "$am_depcomp" conftest.dir
  cd conftest.dir
  # We will build objects and dependencies in a subdirectory because
  # it helps to detect inapplicable dependency modes.  For instance
  # both Tru64's cc and ICC support -MD to output dependencies as a
  # side effect of compilation, but ICC will put the dependencies in
  # the current directory while Tru64 will put them in the object
  # directory.
  mkdir sub

  am_cv_$1_dependencies_compiler_type=none
  if test "$am_compiler_list" = ""; then
     am_compiler_list=`sed -n ['s/^#*\([a-zA-Z0-9]*\))$/\1/p'] < ./depcomp`
  fi
  am__universal=false
  m4_case([$1], [CC],
    [case " $depcc " in #(
     *\ -arch\ *\ -arch\ *) am__universal=true ;;
     esac],
    [CXX],
    [case " $depcc " in #(
     *\ -arch\ *\ -arch\ *) am__universal=true ;;
     esac])

  for depmode in $am_compiler_list; do
    # Setup a source with many dependencies, because some compilers
    # like to wrap large dependency lists on column 80 (with \), and
    # we should not choose a depcomp mode which is confused by this.
    #
    # We need to recreate these files for each test, as the compiler may
    # overwrite some of them when testing with obscure command lines.
    # This happens at least with the AIX C compiler.
    : > sub/conftest.c
    for i in 1 2 3 4 5 6; do
      echo '#include "conftst'$i'.h"' >> sub/conftest.c
      # Using ": > sub/conftst$i.h" creates only sub/conftst1.h with
      # Solaris 10 /bin/sh.
      echo '/* dummy */' > sub/conftst$i.h
    done
    echo "${am__include} ${am__quote}sub/conftest.Po${am__quote}" > confmf

    # We check with '-c' and '-o' for the sake of the "dashmstdout"
    # mode.  It turns out that the SunPro C++ compiler does not properly
    # handle '-M -o', and we need to detect this.  Also, some Intel
    # versions had trouble with output in subdirs.
    am__obj=sub/conftest.${OBJEXT-o}
    am__minus_obj="-o $am__obj"
    case $depmode in
    gcc)
      # This depmode causes a compiler race in universal mode.
      test "$am__universal" = false || continue
      ;;
    nosideeffect)
      # After this tag, mechanisms are not by side-effect, so they'll
      # only be used when explicitly requested.
      if test "x$enable_dependency_tracking" = xyes; then
	continue
      else
	break
      fi
      ;;
    msvc7 | msvc7msys | msvisualcpp | msvcmsys)
      # This compiler won't grok '-c -o', but also, the minuso test has
      # not run yet.  These depmodes are late enough in the game, and
      # so weak that their functioning should not be impacted.
      am__obj=conftest.${OBJEXT-o}
      am__minus_obj=
      ;;
    none) break ;;
    esac
    if depmode=$depmode \
       source=sub/conftest.c object=$am__obj \
       depfile=sub/conftest.Po tmpdepfile=sub/conftest.TPo \
       $SHELL ./depcomp $depcc -c $am__minus_obj sub/conftest.c \
         >/dev/null 2>conftest.err &&
       grep sub/conftst1.h sub/conftest.Po > /dev/null 2>&1 &&
       grep sub/conftst6.h sub/conftest.Po > /dev/null 2>&1 &&
       grep $am__obj sub/conftest.Po > /dev/null 2>&1 &&
       ${MAKE-make} -s -f confmf > /dev/null 2>&1; then
      # icc doesn't choke on unknown options, it will just issue warnings
      # or remarks (even with -Werror).  So we grep stderr for any message
      # that says an option was ignored or not supported.
      # When given -MP, icc 7.0 and 7.1 complain thusly:
      #   icc: Command line warning: ignoring option '-M'; no argument required
      # The diagnosis changed in icc 8.0:
      #   icc: Command line remark: option '-MP' not supported
      if (grep 'ignoring option' conftest.err ||
          grep 'not supported' conftest.err) >/dev/null 2>&1; then :; else
        am_cv_$1_dependencies_compiler_type=$depmode
        break
      fi
    fi
  done

  cd ..
  rm -rf conftest.dir
else
  am_cv_$1_dependencies_compiler_type=none
fi
])
AC_SUBST([$1DEPMODE], [depmode=$am_cv_$1_dependencies_compiler_type])
AM_CONDITIONAL([am__fastdep$1], [
  test "x$enable_dependency_tracking" != xno \
  && test "$am_cv_$1_dependencies_compiler_type" = gcc3])
])


# AM_SET_DEPDIR
# -------------
# Choose a directory name for dependency files.
# This macro is AC_REQUIREd in _AM_DEPENDENCIES.
AC_DEFUN([AM_SET_DEPDIR],
[AC_REQUIRE([AM_SET_LEADING_DOT])dnl
AC_SUBST([DEPDIR], ["${am__leading_dot}deps"])dnl
])


# AM_DEP_TRACK
# ------------
AC_DEFUN([AM_DEP_TRACK],
[AC_ARG_ENABLE([dependency-tracking], [dnl
AS_HELP_STRING(
  [--enable-dependency-tracking],
  [do not reject slow dependency extractors])
AS_HELP_STRING(
  [--disable-dependency-tracking],
  [speeds up one-time build])])
if test "x$enable_dependency_tracking" != xno; then
  am_depcomp="$ac_aux_dir/depcomp"
  AMDEPBACKSLASH='\'
  am__nodep='_no'
fi
AM_CONDITIONAL([AMDEP], [test "x$enable_dependency_tracking" != xno])
AC_SUBST([AMDEPBACKSLASH])dnl
_AM_SUBST_NOTMAKE([AMDEPBACKSLASH])dnl
AC_SUBST([am__nodep])dnl
_AM_SUBST_NOTMAKE([am__nodep])dnl
])

# Generate code to set up dependency tracking.              -*- Autoconf -*-

# Copyright (C) 1999-2014 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.


# _AM_OUTPUT_DEPENDENCY_COMMANDS
# ------------------------------
AC_DEFUN([_AM_OUTPUT_DEPENDENCY_COMMANDS],
[{
  # Older Autoconf quotes --file arguments for eval, but not when files
  # are listed without --file.  Let's play safe and only enable the eval
  # if we detect the quoting.
  case $CONFIG_FILES in
  *\'*) eval set x "$CONFIG_FILES" ;;
  *)   set x $CONFIG_FILES ;;
  esac
  shift
  for mf
  do
    # Strip MF so we end up with the name of the file.
    mf=`echo "$mf" | sed -e 's/:.*$//'`
    # Check whether this is an Automake generated Makefile or not.
    # We used to match only the files named 'Makefile.in', but
    # some people rename them; so instead we look at the file content.
    # Grep'ing the first line is not enough: some people post-process
    # each Makefile.in and add a new line on top of each file to say so.
    # Grep'ing the whole file is not good either: AIX grep has a line
    # limit of 2048, but all sed's we know have understand at least 4000.
    if sed -n 's,^#.*generated by automake.*,X,p' "$mf" | grep X >/dev/null 2>&1; then
      dirpart=`AS_DIRNAME("$mf")`
    else
      continue
    fi
    # Extract the definition of DEPDIR, am__include, and am__quote
    # from the Makefile without running 'make'.
    DEPDIR=`sed -n 's/^DEPDIR = //p' < "$mf"`
    test -z "$DEPDIR" && continue
    am__include=`sed -n 's/^am__include = //p' < "$mf"`
    test -z "$am__include" && continue
    am__quote=`sed -n 's/^am__quote = //p' < "$mf"`
    # Find all dependency output files, they are included files with
    # $(DEPDIR) in their names.  We invoke sed twice because it is the
    # simplest approach to changing $(DEPDIR) to its actual value in the
    # expansion.
    for file in `sed -n "
      s/^$am__include $am__quote\(.*(DEPDIR).*\)$am__quote"'$/\1/p' <"$mf" | \
	 sed -e 's/\$(DEPDIR)/'"$DEPDIR"'/g'`; do
      # Make sure the directory exists.
      test -f "$dirpart/$file" && continue
      fdir=`AS_DIRNAME(["$file"])`
      AS_MKDIR_P([$dirpart/$fdir])
      # echo "creating $dirpart/$file"
      echo '# dummy' > "$dirpart/$file"
    done
  done
}
])# _AM_OUTPUT_DEPENDENCY_COMMANDS


# AM_OUTPUT_DEPENDENCY_COMMANDS
# -----------------------------
# This macro should only be invoked once -- use via AC_REQUIRE.
#
# This code is only required when automatic dependency tracking
# is enabled.  FIXME.  This creates each '.P' file that we will
# need in order to bootstrap the dependency handling code.
AC_DEFUN([AM_OUTPUT_DEPENDENCY_COMMANDS],
[AC_CONFIG_COMMANDS([depfiles],
     [test x"$AMDEP_TRUE" != x"" || _AM_OUTPUT_DEPENDENCY_COMMANDS],
     [AMDEP_TRUE="$AMDEP_TRUE" ac_aux_dir="$ac_aux_dir"])
])

# Do all the work for Automake.                             -*- Autoconf -*-

# Copyright (C) 1996-2014 Free Software Foundation, Inc.
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
  m4_ifdef([AC_PACKAGE_NAME], [ok]):m4_ifdef([AC_PACKAGE_VERSION], [ok]),
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
# <http://lists.gnu.org/archive/html/automake/2012-07/msg00001.html>
# <http://lists.gnu.org/archive/html/automake/2012-07/msg00014.html>
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
that behaves properly: <http://www.gnu.org/software/coreutils/>.

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

# Copyright (C) 2001-2014 Free Software Foundation, Inc.
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

# Copyright (C) 2003-2014 Free Software Foundation, Inc.
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

# Check to see how 'make' treats includes.	            -*- Autoconf -*-

# Copyright (C) 2001-2014 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# AM_MAKE_INCLUDE()
# -----------------
# Check to see how make treats includes.
AC_DEFUN([AM_MAKE_INCLUDE],
[am_make=${MAKE-make}
cat > confinc << 'END'
am__doit:
	@echo this is the am__doit target
.PHONY: am__doit
END
# If we don't find an include directive, just comment out the code.
AC_MSG_CHECKING([for style of include used by $am_make])
am__include="#"
am__quote=
_am_result=none
# First try GNU make style include.
echo "include confinc" > confmf
# Ignore all kinds of additional output from 'make'.
case `$am_make -s -f confmf 2> /dev/null` in #(
*the\ am__doit\ target*)
  am__include=include
  am__quote=
  _am_result=GNU
  ;;
esac
# Now try BSD make style include.
if test "$am__include" = "#"; then
   echo '.include "confinc"' > confmf
   case `$am_make -s -f confmf 2> /dev/null` in #(
   *the\ am__doit\ target*)
     am__include=.include
     am__quote="\""
     _am_result=BSD
     ;;
   esac
fi
AC_SUBST([am__include])
AC_SUBST([am__quote])
AC_MSG_RESULT([$_am_result])
rm -f confinc confmf
])

# Fake the existence of programs that GNU maintainers use.  -*- Autoconf -*-

# Copyright (C) 1997-2014 Free Software Foundation, Inc.
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
  case $am_aux_dir in
  *\ * | *\	*)
    MISSING="\${SHELL} \"$am_aux_dir/missing\"" ;;
  *)
    MISSING="\${SHELL} $am_aux_dir/missing" ;;
  esac
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

# Copyright (C) 2001-2014 Free Software Foundation, Inc.
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

# Copyright (C) 1999-2014 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# _AM_PROG_CC_C_O
# ---------------
# Like AC_PROG_CC_C_O, but changed for automake.  We rewrite AC_PROG_CC
# to automatically call this.
AC_DEFUN([_AM_PROG_CC_C_O],
[AC_REQUIRE([AM_AUX_DIR_EXPAND])dnl
AC_REQUIRE_AUX_FILE([compile])dnl
AC_LANG_PUSH([C])dnl
AC_CACHE_CHECK(
  [whether $CC understands -c and -o together],
  [am_cv_prog_cc_c_o],
  [AC_LANG_CONFTEST([AC_LANG_PROGRAM([])])
  # Make sure it works both with $CC and with simple cc.
  # Following AC_PROG_CC_C_O, we do the test twice because some
  # compilers refuse to overwrite an existing .o file with -o,
  # though they will create one.
  am_cv_prog_cc_c_o=yes
  for am_i in 1 2; do
    if AM_RUN_LOG([$CC -c conftest.$ac_ext -o conftest2.$ac_objext]) \
         && test -f conftest2.$ac_objext; then
      : OK
    else
      am_cv_prog_cc_c_o=no
      break
    fi
  done
  rm -f core conftest*
  unset am_i])
if test "$am_cv_prog_cc_c_o" != yes; then
   # Losing compiler, so override with the script.
   # FIXME: It is wrong to rewrite CC.
   # But if we don't then we get into trouble of one sort or another.
   # A longer-term fix would be to have automake use am__CC in this case,
   # and then we could set am__CC="\$(top_srcdir)/compile \$(CC)"
   CC="$am_aux_dir/compile $CC"
fi
AC_LANG_POP([C])])

# For backward compatibility.
AC_DEFUN_ONCE([AM_PROG_CC_C_O], [AC_REQUIRE([AC_PROG_CC])])

# Copyright (C) 2001-2014 Free Software Foundation, Inc.
#
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# AM_RUN_LOG(COMMAND)
# -------------------
# Run COMMAND, save the exit status in ac_status, and log it.
# (This has been adapted from Autoconf's _AC_RUN_LOG macro.)
AC_DEFUN([AM_RUN_LOG],
[{ echo "$as_me:$LINENO: $1" >&AS_MESSAGE_LOG_FD
   ($1) >&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD
   ac_status=$?
   echo "$as_me:$LINENO: \$? = $ac_status" >&AS_MESSAGE_LOG_FD
   (exit $ac_status); }])

# Check to make sure that the build environment is sane.    -*- Autoconf -*-

# Copyright (C) 1996-2014 Free Software Foundation, Inc.
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

# Copyright (C) 2009-2014 Free Software Foundation, Inc.
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

# Copyright (C) 2001-2014 Free Software Foundation, Inc.
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

# Copyright (C) 2006-2014 Free Software Foundation, Inc.
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

# Copyright (C) 2004-2014 Free Software Foundation, Inc.
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


#
# Support XEN
#
AC_DEFUN([SET_XEN_INCLUDES],
[
XEN_INCLUDES=
LB_LINUX_CONFIG([XEN],[XEN_INCLUDES="-I$LINUX/arch/x86/include/mach-xen"],[])
LB_LINUX_CONFIG_VALUE([XEN_INTERFACE_VERSION],[XEN_INCLUDES="$XEN_INCLUDES -D__XEN_INTERFACE_VERSION__=$res"],[XEN_INCLUDES="$XEN_INCLUDES -D__XEN_INTERFACE_VERSION__=$res"])
])

#
# LB_LINUX_VERSION
#
# Set things accordingly for a linux kernel
#
AC_DEFUN([LB_LINUX_VERSION],[
KMODEXT=".ko"
AC_SUBST(KMODEXT)
]
)


#
# LB_LINUX_RELEASE
#
# get the release version of linux
#
AC_DEFUN([LB_LINUX_RELEASE],
[
LINUXRELEASE=$(LB_LINUX_MAKE_OUTPUT([kernelrelease]))
if test x$LINUXRELEASE = x ; then
	# Workaround for some kernel 6.3 RCs:
	LINUXRELEASE=`cat $LINUX_OBJ/include/config/kernel.release 2>/dev/null`
	if test "$LINUXRELEASE" = ''; then
		AC_MSG_RESULT([unknown])
		AC_MSG_ERROR([Could not determine Linux release version from linux/version.h.])
	fi
fi
AC_MSG_RESULT([$LINUXRELEASE])
AC_SUBST(LINUXRELEASE)

moduledir='/lib/modules/'$LINUXRELEASE/updates/kernel
AC_SUBST(moduledir)

modulefsdir='$(moduledir)/fs/$(PACKAGE)'
AC_SUBST(modulefsdir)

modulenetdir='$(moduledir)/net/$(PACKAGE)'
AC_SUBST(modulenetdir)

# ------------ RELEASE --------------------------------
AC_MSG_CHECKING([for MLNX release])
AC_ARG_WITH([release],
	AC_HELP_STRING([--with-release=string],
		       [set the release string (default=$kvers_YYYYMMDDhhmm)]),
	[RELEASE=$withval],
	RELEASE=""
	if test -n "$DOWNSTREAM_RELEASE"; then
		RELEASE="${DOWNSTREAM_RELEASE}_"
	fi
	RELEASE="$RELEASE`echo ${LINUXRELEASE} | tr '-' '_'`_$BUILDID")
AC_MSG_RESULT($RELEASE)
AC_SUBST(RELEASE)

# check is redhat/suse kernels
AC_MSG_CHECKING([that RedHat kernel])
LB_LINUX_TRY_COMPILE([
		#include <linux/version.h>
	],[
		#ifndef RHEL_RELEASE_CODE
		#error "not redhat kernel"
		#endif
	],[
		RHEL_KERNEL="yes"
		AC_MSG_RESULT([yes])
	],[
	        AC_MSG_RESULT([no])
])

LB_LINUX_CONFIG([SUSE_KERNEL],[SUSE_KERNEL="yes"],[])

])

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
	if readlink -q -e $DEFAULT_LINUX; then
		break
	fi
done
if test "$DEFAULT_LINUX" = "/lib/modules/$(uname -r)/source"; then
	PATHS="/lib/modules/$(uname -r)/build"
fi
PATHS="$PATHS $DEFAULT_LINUX"
for DEFAULT_LINUX_OBJ in $PATHS; do
	if readlink -q -e $DEFAULT_LINUX_OBJ; then
		break
	fi
done
AC_MSG_CHECKING([for Linux sources])
AC_ARG_WITH([linux],
	AC_HELP_STRING([--with-linux=path],
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
	AC_HELP_STRING([--with-linux-obj=path],
			[set path to Linux objects dir (default=/lib/modules/$(uname -r)/build,/usr/src/linux)]),
	[LB_ARG_CANON_PATH([linux-obj], [LINUX_OBJ])],
	[LINUX_OBJ=$DEFAULT_LINUX_OBJ])

AC_MSG_RESULT([$LINUX_OBJ])
AC_SUBST(LINUX_OBJ)

# -------- check for .config --------
AC_ARG_WITH([linux-config],
	[AC_HELP_STRING([--with-linux-config=path],
			[set path to Linux .conf (default=$LINUX_OBJ/include/config/auto.conf)])],
	[LB_ARG_CANON_PATH([linux-config], [LINUX_CONFIG])],
	[LINUX_CONFIG=$LINUX_OBJ/include/config/auto.conf])
AC_SUBST(LINUX_CONFIG)

LB_CHECK_FILE([/boot/kernel.h],
	[KERNEL_SOURCE_HEADER='/boot/kernel.h'],
	[LB_CHECK_FILE([/var/adm/running-kernel.h],
		[KERNEL_SOURCE_HEADER='/var/adm/running-kernel.h'])])

AC_ARG_WITH([kernel-source-header],
	AC_HELP_STRING([--with-kernel-source-header=path],
			[Use a different kernel version header.  Consult build/README.kernel-source for details.]),
	[LB_ARG_CANON_PATH([kernel-source-header], [KERNEL_SOURCE_HEADER])])

# ------------ .config exists ----------------
LB_CHECK_FILE([$LINUX_CONFIG],[],
	[AC_MSG_ERROR([Kernel config could not be found.  If you are building from a kernel-source rpm consult build/README.kernel-source])])

# ----------- kconfig.h exists ---------------
# kernel 3.1, $LINUX/include/linux/kconfig.h is added
# see kernel commit 2a11c8ea20bf850b3a2c60db8c2e7497d28aba99
LB_CHECK_FILE([$LINUX/include/linux/kconfig.h],
              [CONFIG_INCLUDE=$LINUX/include/linux/kconfig.h],
              [CONFIG_INCLUDE=$LINUX/include/generated/kconfig.h])
	AC_SUBST(CONFIG_INCLUDE)

if test -e $CONFIG_INCLUDE; then
	CONFIG_INCLUDE_FLAG="-include $CONFIG_INCLUDE"
fi

# ------------ rhconfig.h includes runtime-generated bits --
# red hat kernel-source checks

# we know this exists after the check above.  if the user
# tarred up the tree and ran make dep etc. in it, then
# version.h gets overwritten with a standard linux one.
#
if (grep -q rhconfig $LINUX_OBJ/include/linux/version.h 2>/dev/null) ||
   (grep -q rhconfig $LINUX_OBJ/include/generated/uapi/linux/version.h 2>/dev/null) ; then
	# This is a clean kernel-source tree, we need to
	# enable extensive workarounds to get this to build
	# modules
	LB_CHECK_FILE([$KERNEL_SOURCE_HEADER],
		[if test $KERNEL_SOURCE_HEADER = '/boot/kernel.h' ; then
			AC_MSG_WARN([Using /boot/kernel.h from RUNNING kernel.])
			AC_MSG_WARN([If this is not what you want, use --with-kernel-source-header.])
			AC_MSG_WARN([Consult build/README.kernel-source for details.])
		fi],
		[AC_MSG_ERROR([$KERNEL_SOURCE_HEADER not found.  Consult build/README.kernel-source for details.])])
	EXTRA_KCFLAGS="-include $KERNEL_SOURCE_HEADER $EXTRA_KCFLAGS"
fi

# this is needed before we can build modules
SET_BUILD_ARCH
LB_LINUX_CROSS
LB_LINUX_VERSION
SET_XEN_INCLUDES

# --- check that we can build modules at all
AC_MSG_CHECKING([that modules can be built at all])
LB_LINUX_TRY_COMPILE([],[],[
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
	AC_MSG_WARN([Consult config.log for details.])
	AC_MSG_WARN([If you are trying to build with a kernel-source rpm, consult build/README.kernel-source])
	AC_MSG_ERROR([Kernel modules cannot be built.])
])

LB_LINUX_RELEASE
]) # end of LB_LINUX_PATH

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
# LB_LINUX_CROSS
#
# check for cross compilation
#
AC_DEFUN([LB_LINUX_CROSS],
	[AC_MSG_CHECKING([for cross compilation])
CROSS_VARS=
case $target_vendor in
	# The K1OM architecture is an extension of the x86 architecture.
	# So, the $target_arch is x86_64.
	k1om)
		AC_MSG_RESULT([Intel(R) Xeon Phi(TM)])
		CC_TARGET_ARCH=`$CC -v 2>&1 | grep Target: | sed -e 's/Target: //'`
		if test $CC_TARGET_ARCH != x86_64-$target_vendor-linux ; then
			AC_MSG_ERROR([Cross compiler not found in PATH.])
		fi
		CROSS_VARS="ARCH=$target_vendor CROSS_COMPILE=x86_64-$target_vendor-linux-"
		CCAS=$CC
		if test x$enable_server = xyes ; then
			AC_MSG_WARN([Disabling server (not supported for x86_64-$target_vendor-linux).])
			enable_server='no'
		fi
		;;
	*)
		CROSS_VARS="CROSS_COMPILE=$CROSS_COMPILE"
		AC_MSG_RESULT([no])
		;;
esac
AC_SUBST(CROSS_VARS)
])

# these are like AC_TRY_COMPILE, but try to build modules against the
# kernel, inside the build directory

# LB_LANG_PROGRAM(C)([PROLOGUE], [BODY])
# --------------------------------------
m4_define([LB_LANG_PROGRAM],
[
#include <linux/kernel.h>
$1
int
main (void)
{
dnl Do *not* indent the following line: there may be CPP directives.
dnl Don't move the `;' right after for the same reason.
$2
  ;
  return 0;
}])


#
# LB_LINUX_MAKE_OUTPUT
#
# Runs a make target ($1, potentially with extra flags)
# output goes to standard output.
#
AC_DEFUN([LB_LINUX_MAKE_OUTPUT],
[
MAKE=${MAKE:-make}
$MAKE -s M=$PWD -C $LINUX_OBJ $1
])

#
# LB_LINUX_COMPILE_IFELSE
#
# like AC_COMPILE_IFELSE
#
AC_DEFUN([LB_LINUX_COMPILE_IFELSE],
[m4_ifvaln([$1], [AC_LANG_CONFTEST([$1])])dnl
MAKE=${MAKE:-make}
rm -f build/conftest.o build/conftest.mod.c build/conftest.ko build/output.log
AS_IF([AC_TRY_COMMAND(cp conftest.c build && env $CROSS_VARS $MAKE -d [$2] ${LD:+"LD=$CROSS_COMPILE$LD"} CC="$CROSS_COMPILE$CC" -f $PWD/build/Makefile MLNX_LINUX_CONFIG=$LINUX_CONFIG LINUXINCLUDE="-include generated/autoconf.h $XEN_INCLUDES $EXTRA_MLNX_INCLUDE -I$LINUX/arch/$SRCARCH/include -Iarch/$SRCARCH/include/generated -Iinclude -I$LINUX/arch/$SRCARCH/include/uapi -Iarch/$SRCARCH/include/generated/uapi -I$LINUX/include -I$LINUX/include/uapi -Iinclude/generated/uapi  -I$LINUX/arch/$SRCARCH/include -Iarch/$SRCARCH/include/generated -I$LINUX/arch/$SRCARCH/include -I$LINUX/arch/$SRCARCH/include/generated -I$LINUX_OBJ/include -I$LINUX/include -I$LINUX_OBJ/include2 $CONFIG_INCLUDE_FLAG" -o tmp_include_depends -o scripts -o include/config/MARKER -C $LINUX_OBJ EXTRA_CFLAGS="-Werror-implicit-function-declaration -Wno-unused-variable -Wno-uninitialized $EXTRA_KCFLAGS" $CROSS_VARS M=$PWD/build >/dev/null 2>build/output.log; [[[ $? -ne 0 ]]] && cat build/output.log 1>&2 && false || config/warning_filter.sh build/output.log) >/dev/null && AC_TRY_COMMAND([$3])],
	[$4],
	[_AC_MSG_LOG_CONFTEST
m4_ifvaln([$5],[$5])dnl])
rm -f build/conftest.o build/conftest.mod.c build/conftest.mod.o build/conftest.ko m4_ifval([$1], [build/conftest.c conftest.c])[]dnl
])

#
# LB_LINUX_ARCH
#
# Determine the kernel's idea of the current architecture
#
AC_DEFUN([LB_LINUX_ARCH],
         [AC_MSG_CHECKING([Linux kernel architecture])
          AS_IF([rm -f $PWD/build/arch
                 make -s --no-print-directory echoarch -f $PWD/build/Makefile \
                     MLNX_LINUX_CONFIG=$LINUX_CONFIG -C $LINUX $CROSS_VARS  \
                     ARCHFILE=$PWD/build/arch && LINUX_ARCH=`cat $PWD/build/arch`],
                [AC_MSG_RESULT([$LINUX_ARCH])],
                [AC_MSG_ERROR([Could not determine the kernel architecture.])])
          rm -f build/arch])

#
# LB_LINUX_TRY_COMPILE
#
# like AC_TRY_COMPILE
#
AC_DEFUN([LB_LINUX_TRY_COMPILE],
[LB_LINUX_COMPILE_IFELSE(
	[AC_LANG_SOURCE([LB_LANG_PROGRAM([[$1]], [[$2]])])],
	[modules],
	[test -s build/conftest.o],
	[$3], [$4])])

#
# LB_LINUX_CONFIG
#
# check if a given config option is defined
#
AC_DEFUN([LB_LINUX_CONFIG],[
	AC_MSG_CHECKING([if Linux was built with CONFIG_$1])
	LB_LINUX_TRY_COMPILE([
		#include <generated/autoconf.h>
	],[
		#ifndef CONFIG_$1
		#error CONFIG_$1 not #defined
		#endif
	],[
		AC_MSG_RESULT([yes])
		$2
	],[
		AC_MSG_RESULT([no])
		$3
	])
])

#
# LB_LINUX_CONFIG_IM
#
# check if a given config option is builtin or as module
#
AC_DEFUN([LB_LINUX_CONFIG_IM],[
	AC_MSG_CHECKING([if Linux was built with CONFIG_$1 in or as module])
	LB_LINUX_TRY_COMPILE([
		#include <generated/autoconf.h>
	],[
		#if !(defined(CONFIG_$1) || defined(CONFIG_$1_MODULE))
		#error CONFIG_$1 and CONFIG_$1_MODULE not #defined
		#endif
	],[
		AC_MSG_RESULT([yes])
		$2
	],[
		AC_MSG_RESULT([no])
		$3
	])
])

#
# LB_LINUX_TRY_MAKE
#
# like LB_LINUX_TRY_COMPILE, but with different arguments
#
AC_DEFUN([LB_LINUX_TRY_MAKE],
	[LB_LINUX_COMPILE_IFELSE(
		[AC_LANG_SOURCE([LB_LANG_PROGRAM([[$1]], [[$2]])])],
		[$3], [$4], [$5], [$6]
	)]
)

#
# LB_CONFIG_COMPAT_RDMA
#
AC_DEFUN([LB_CONFIG_COMPAT_RDMA],
[AC_MSG_CHECKING([whether to use Compat RDMA])
# set default
AC_ARG_WITH([o2ib],
	AC_HELP_STRING([--with-o2ib=path],
		       [build o2iblnd against path]),
	[
		case $with_o2ib in
		yes)    O2IBPATHS="$LINUX $LINUX/drivers/infiniband"
			ENABLEO2IB=2
			;;
		no)     ENABLEO2IB=0
			;;
		*)      O2IBPATHS=$with_o2ib
			ENABLEO2IB=3
			;;
		esac
	],[
		O2IBPATHS="$LINUX $LINUX/drivers/infiniband"
		ENABLEO2IB=1
	])
if test $ENABLEO2IB -eq 0; then
	AC_MSG_RESULT([no])
else
	o2ib_found=false
	for O2IBPATH in $O2IBPATHS; do
		if test \( -f ${O2IBPATH}/include/rdma/rdma_cm.h -a \
			   -f ${O2IBPATH}/include/rdma/ib_cm.h -a \
			   -f ${O2IBPATH}/include/rdma/ib_verbs.h -a \
			   -f ${O2IBPATH}/include/rdma/ib_fmr_pool.h \); then
			o2ib_found=true
			break
		fi
	done
	compatrdma_found=false
	if $o2ib_found; then
		if test \( -f ${O2IBPATH}/include/linux/compat-2.6.h \); then
			compatrdma_found=true
			AC_MSG_RESULT([yes])
			AC_DEFINE(HAVE_COMPAT_RDMA, 1, [compat rdma found])
		else
			AC_MSG_RESULT([no])
		fi
	fi
fi
])

#
# LB_CONFIG_OFED_BACKPORTS
#
# include any OFED backport headers in all compile commands
# NOTE: this does only include the backport paths, not the OFED headers
#       adding the OFED headers is done in the lnet portion
AC_DEFUN([LB_CONFIG_OFED_BACKPORTS],
[AC_MSG_CHECKING([whether to use any OFED backport headers])
if test $ENABLEO2IB -eq 0; then
	AC_MSG_RESULT([no])
else
	if ! $o2ib_found; then
		AC_MSG_RESULT([no])
		case $ENABLEO2IB in
			1) ;;
			2) AC_MSG_ERROR([kernel OpenIB gen2 headers not present]);;
			3) AC_MSG_ERROR([bad --with-o2ib path]);;
			*) AC_MSG_ERROR([internal error]);;
		esac
	else
		if ! $compatrdma_found; then
                	if test -f $O2IBPATH/config.mk; then
				. $O2IBPATH/config.mk
			elif test -f $O2IBPATH/ofed_patch.mk; then
				. $O2IBPATH/ofed_patch.mk
			fi
		fi
		if test -n "$BACKPORT_INCLUDES"; then
			OFED_BACKPORT_PATH="$O2IBPATH/${BACKPORT_INCLUDES/*\/kernel_addons/kernel_addons}/"
			EXTRA_LNET_INCLUDE="-I$OFED_BACKPORT_PATH $EXTRA_LNET_INCLUDE"
			AC_MSG_RESULT([yes])
		else
			AC_MSG_RESULT([no])
		fi
	fi
fi
])

# LC_MODULE_LOADING
# after 2.6.28 CONFIG_KMOD is removed, and only CONFIG_MODULES remains
# so we test if request_module is implemented or not
AC_DEFUN([LC_MODULE_LOADING],
[AC_MSG_CHECKING([if kernel module loading is possible])
LB_LINUX_TRY_MAKE([
	#include <linux/kmod.h>
],[
	int myretval=ENOSYS ;
	return myretval;
],[
	MLNX_KERNEL_TEST=conftest.i
],[dnl
	grep request_module build/conftest.i |dnl
		grep -v `grep "int myretval=" build/conftest.i |dnl
			cut -d= -f2 | cut -d" "  -f1`dnl
		>/dev/null dnl
],[
	AC_MSG_RESULT(yes)
	AC_DEFINE(HAVE_MODULE_LOADING_SUPPORT, 1,
		  [kernel module loading is possible])
],[
	AC_MSG_RESULT(no)
	AC_MSG_WARN([])
	AC_MSG_WARN([Kernel module loading support is highly recommended.])
	AC_MSG_WARN([])
])
])

#
# LB_PROG_LINUX
#
# linux tests
#
AC_DEFUN([LB_PROG_LINUX],
[LB_LINUX_PATH
LB_LINUX_ARCH
LB_LINUX_SYMVERFILE


LB_LINUX_CONFIG([MODULES],[],[
	AC_MSG_ERROR([module support is required to build MLNX kernel modules.])
])

LB_LINUX_CONFIG([MODVERSIONS])

LB_LINUX_CONFIG([KALLSYMS],[],[
	AC_MSG_ERROR([compat_mlnx requires that CONFIG_KALLSYMS is enabled in your kernel.])
])

# 2.6.28
LC_MODULE_LOADING

LB_CONFIG_COMPAT_RDMA

# it's ugly to be doing anything with OFED outside of the lnet module, but
# this has to be done here so that the backports path is set before all of
# the LN_PROG_LINUX checks are done
LB_CONFIG_OFED_BACKPORTS
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

#
# Like AC_CHECK_HEADER but checks for a kernel-space header
#
m4_define([LB_CHECK_LINUX_HEADER],
[AS_VAR_PUSHDEF([ac_Header], [ac_cv_header_$1])dnl
AC_CACHE_CHECK([for $1], ac_Header,
	       [LB_LINUX_COMPILE_IFELSE([LB_LANG_PROGRAM([@%:@include <$1>])],
				  [modules],
				  [test -s build/conftest.o],
				  [AS_VAR_SET(ac_Header, [yes])],
				  [AS_VAR_SET(ac_Header, [no])])])
AS_IF([test AS_VAR_GET(ac_Header) = yes], [$2], [$3])[]dnl
AS_VAR_POPDEF([ac_Header])dnl
])

#
# LB_USES_DPKG
#
# Determine if the target is a dpkg system or rpm
#
AC_DEFUN([LB_USES_DPKG],
[
AC_MSG_CHECKING([if this distro uses dpkg])
case `lsb_release -i -s 2>/dev/null` in
        Ubuntu | Debian)
                AC_MSG_RESULT([yes])
                uses_dpkg=yes
                ;;
        *)
                AC_MSG_RESULT([no])
                uses_dpkg=no
                ;;
esac
])

#
# LB_PROG_CC
#
# checks on the C compiler
#
AC_DEFUN([LB_PROG_CC],
[AC_PROG_RANLIB
AC_CHECK_TOOL(LD, ld, [no])
AC_CHECK_TOOL(OBJDUMP, objdump, [no])
AC_CHECK_TOOL(STRIP, strip, [no])

# ---------  unsigned long long sane? -------
AC_CHECK_SIZEOF(unsigned long long, 0)
echo "---> size SIZEOF $SIZEOF_unsigned_long_long"
echo "---> size SIZEOF $ac_cv_sizeof_unsigned_long_long"
if test $ac_cv_sizeof_unsigned_long_long != 8 ; then
	AC_MSG_ERROR([** we assume that sizeof(long long) == 8.])
fi

if test $target_cpu == "powerpc64"; then
	AC_MSG_WARN([set compiler with -m64])
	CFLAGS="$CFLAGS -m64"
	CC="$CC -m64"
fi
])

# LB_CONTITIONALS
#
AC_DEFUN([LB_CONDITIONALS],
[
AM_CONDITIONAL(ARCH_x86, test x$target_cpu = "xx86_64" -o x$target_cpu = "xi686")

AC_OUTPUT

cat <<_ACEOF

CC:            $CC
LD:            $LD
CFLAGS:        $CFLAGS
EXTRA_KCFLAGS: $EXTRA_KCFLAGS

Type 'make' to build kernel modules.
_ACEOF
])

#
# SET_BUILD_ARCH
#
AC_DEFUN([SET_BUILD_ARCH],
[
AC_MSG_CHECKING([for build ARCH])
SRCARCH=${ARCH:-$(uname -m)}
SRCARCH=$(echo $SRCARCH | sed -e s/i.86/x86/ \
			-e s/x86_64/x86/ \
			-e s/ppc.*/powerpc/ \
			-e 's/powerpc64/powerpc/' \
			-e s/aarch64.*/arm64/ \
			-e s/sparc32.*/sparc/ \
			-e s/sparc64.*/sparc/ \
			-e s/s390x/s390/)

# very old kernels had different strucure under arch dir
if [[ "X$SRCARCH" == "Xx86" ]] && ! [[ -d "$LINUX/arch/x86" ]]; then
	SRCARCH=x86_64
fi

AC_MSG_RESULT([ARCH=$ARCH, SRCARCH=$SRCARCH])
])

#
# LB_LINUX_CONFIG_VALUE
#
#  get a given config's option value
#
AC_DEFUN([LB_LINUX_CONFIG_VALUE],[
	AC_MSG_CHECKING([get value of CONFIG_$1])
	if (grep -q "^#define CONFIG_$1 " $LINUX_OBJ/include/generated/autoconf.h 2>/dev/null); then
		res=$(grep "^#define CONFIG_$1 " $LINUX_OBJ/include/generated/autoconf.h 2>/dev/null | cut -d' ' -f'3')
		AC_MSG_RESULT([$1 value is '$res'])
		$2
	else
		AC_MSG_RESULT([$1 in not defined in autoconf.h])
		$3
	fi
])

#
# This file defines macros used to manage and support running
# build tests in parallel.
#

#
# Prepare stuff for parralel build jobs process
#
AC_DEFUN([MLNX_PARALLEL_INIT_ONCE],
[
if [[ "X${RAN_MLNX_PARALLEL_INIT_ONCE}" != "X1" ]]; then
	MAX_JOBS=${NJOBS:-1}
	RAN_MLNX_PARALLEL_INIT_ONCE=1
	/bin/rm -rf CONFDEFS_H_DIR
	/bin/mkdir -p CONFDEFS_H_DIR
	declare -i CONFDEFS_H_INDEX=0
	declare -i RUNNING_JOBS=0
fi
])

#
# MLNX_AC_DEFINE(VARIABLE, [VALUE], [DESCRIPTION])
# -------------------------------------------
# Set VARIABLE to VALUE, verbatim, or 1.  Remember the value
# and if VARIABLE is affected the same VALUE, do nothing, else
# die.  The third argument is used by autoheader.
m4_define([MLNX_AC_DEFINE], [_MLNX_AC_DEFINE_Q([\], $@)])


# _MLNX_AC_DEFINE_Q(QUOTE, VARIABLE, [VALUE], [DESCRIPTION])
# -----------------------------------------------------
# Internal function that performs common elements of AC_DEFINE{,_UNQUOTED}.
#
# m4_index is roughly 5 to 8 times faster than m4_bpatsubst, so only
# use the regex when necessary.  AC_name is defined with over-quotation,
# so that we can avoid m4_defn.
m4_define([_MLNX_AC_DEFINE_Q],
[m4_pushdef([AC_name], m4_if(m4_index([$2], [(]), [-1], [[[$2]]],
			     [m4_bpatsubst([[[$2]]], [(.*)])]))dnl
AC_DEFINE_TRACE(AC_name)dnl
m4_cond([m4_index([$3], [
])], [-1], [],
	[AS_LITERAL_IF([$3], [m4_bregexp([[$3]], [[^\\]
], [-])])], [], [],
	[m4_warn([syntax], [AC_DEFINE]m4_ifval([$1], [], [[_UNQUOTED]])dnl
[: `$3' is not a valid preprocessor define value])])dnl
m4_ifval([$4], [AH_TEMPLATE(AC_name, [$4])])dnl
cat >>CONFDEFS_H_DIR/confdefs.h.${CONFDEFS_H_INDEX} <<$1_ACEOF
[@%:@define] $2 m4_if([$#], 2, 1, [$3], [], [/**/], [$3])
_ACEOF
])

# MLNX_AC_LANG_SOURCE(C)(BODY)
# -----------------------
# We can't use '#line $LINENO "configure"' here, since
# Sun c89 (Sun WorkShop 6 update 2 C 5.3 Patch 111679-08 2002/05/09)
# rejects $LINENO greater than 32767, and some configure scripts
# are longer than 32767 lines.
m4_define([MLNX_AC_LANG_SOURCE(C)],
[/* confdefs.h.  */
_ACEOF
cat confdefs.h >>$tmpbuild/conftest.$ac_ext
cat >>$tmpbuild/conftest.$ac_ext <<_ACEOF
/* end confdefs.h.  */
$1])

# MLNX_AC_LANG_SOURCE(BODY)
# --------------------
# Produce a valid source for the current language, which includes the
# BODY, and as much as possible `confdefs.h'.
AC_DEFUN([MLNX_AC_LANG_SOURCE],
[_AC_LANG_DISPATCH([$0], _AC_LANG, $@)])


# MLNX_AC_LANG_CONFTEST(BODY)
# ----------------------
# Save the BODY in `conftest.$ac_ext'.  Add a trailing new line.
AC_DEFUN([MLNX_AC_LANG_CONFTEST],
[cat >$tmpbuild/conftest.$ac_ext <<_ACEOF
$1
_ACEOF])

# _MLNX_AC_MSG_LOG_CONFTEST
# --------------------
m4_define([_MLNX_AC_MSG_LOG_CONFTEST],
[AS_ECHO(["$as_me: failed program was:"]) >&AS_MESSAGE_LOG_FD
sed 's/^/| /' $tmpbuild/conftest.$ac_ext >&AS_MESSAGE_LOG_FD
])


#
# MLNX_LB_LINUX_COMPILE_IFELSE
#
# like AC_COMPILE_IFELSE.
# runs in a temp dir
#
AC_DEFUN([MLNX_LB_LINUX_COMPILE_IFELSE],
[
{
MAKE=${MAKE:-make}
tmpbuild=$(/bin/mktemp -d $PWD/build/build_XXXXX)
/bin/cp build/Makefile $tmpbuild/
m4_ifvaln([$1], [MLNX_AC_LANG_CONFTEST([$1])])dnl
AS_IF([AC_TRY_COMMAND(env $CROSS_VARS $MAKE -d [$2] ${LD:+"LD=$CROSS_COMPILE$LD"} CC="$CROSS_COMPILE$CC" -f $tmpbuild/Makefile MLNX_LINUX_CONFIG=$LINUX_CONFIG LINUXINCLUDE="-include generated/autoconf.h $XEN_INCLUDES $EXTRA_MLNX_INCLUDE -I$LINUX/arch/$SRCARCH/include -Iarch/$SRCARCH/include/generated -Iinclude -I$LINUX/arch/$SRCARCH/include/uapi -Iarch/$SRCARCH/include/generated/uapi -I$LINUX/include -I$LINUX/include/uapi -Iinclude/generated/uapi  -I$LINUX/arch/$SRCARCH/include -Iarch/$SRCARCH/include/generated -I$LINUX/arch/$SRCARCH/include -I$LINUX/arch/$SRCARCH/include/generated -I$LINUX_OBJ/include -I$LINUX/include -I$LINUX_OBJ/include2 $CONFIG_INCLUDE_FLAG" -o tmp_include_depends -o scripts -o include/config/MARKER -C $LINUX_OBJ EXTRA_CFLAGS="-Werror-implicit-function-declaration -Wno-unused-variable -Wno-uninitialized $EXTRA_KCFLAGS" $CROSS_VARS M=$tmpbuild >/dev/null 2>$tmpbuild/output.log; [[[ $? -ne 0 ]]] && cat $tmpbuild/output.log 1>&2 && false || config/warning_filter.sh $tmpbuild/output.log) >/dev/null && AC_TRY_COMMAND([$3])],
	[$4],
	[_MLNX_AC_MSG_LOG_CONFTEST
m4_ifvaln([$5],[$5])dnl])
/bin/rm -rf $tmpbuild
}
])

#
# MLNX_LB_LINUX_TRY_COMPILE
#
# like AC_TRY_COMPILE
#
AC_DEFUN([MLNX_LB_LINUX_TRY_COMPILE],
[MLNX_LB_LINUX_COMPILE_IFELSE(
	[MLNX_AC_LANG_SOURCE([LB_LANG_PROGRAM([[$1]], [[$2]])])],
	[modules],
	[test -s $tmpbuild/conftest.o],
	[$3], [$4])])

# MLNX_BG_LB_LINUX_COMPILE_IFELSE
#
# Do fork and call LB_LINUX_COMPILE_IFELSE
# to run the build test in background
#
AC_DEFUN([MLNX_BG_LB_LINUX_TRY_COMPILE],
[
# init stuff
MLNX_PARALLEL_INIT_ONCE

# wait if there are MAX_JOBS tests running
if [[ $RUNNING_JOBS -eq $MAX_JOBS ]]; then
	wait
	RUNNING_JOBS=0
else
	let RUNNING_JOBS++
fi

# inc header index
let CONFDEFS_H_INDEX++

# run test in background if MAX_JOBS > 1
if [[ $MAX_JOBS -eq 1 ]]; then
MLNX_LB_LINUX_TRY_COMPILE([$1], [$2], [$3], [$4])
else
{
MLNX_LB_LINUX_TRY_COMPILE([$1], [$2], [$3], [$4])
}&
fi
])


/nl Examine kernel functionality

# Add your defines ONLY in LINUX_CONFIG_COMPAT section
AC_DEFUN([LINUX_CONFIG_COMPAT],
[
	AC_MSG_CHECKING([if dpll_pin_ops.lock_status_get has status_error])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/dpll.h>

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
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_LOCK_STATUS_GET_GET_ERROR_STATUS, 1,
			  [dpll_pin_ops.lock_status_get has status_error])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct dpll_pin_ops exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <linux/dpll.h>
	],[
		struct dpll_pin_ops *pin_ops = NULL;
		struct dpll_device_ops *devce_ops = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DPLL_STRUCTS, 1,
			[have struct dpll_pin_ops])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct dpll_pin_ops has ffo_get])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <linux/dpll.h>
	],[
		struct dpll_pin_ops pin_ops;

		pin_ops.ffo_get = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DPLL_PIN_OPS_HAS_FFO_GET, 1,
			[struct dpll_pin_ops has ffo_get])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if dpll.h has dpll_netdev_pin_set])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <linux/dpll.h>
	],[
		dpll_netdev_pin_set(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DPLL_NETDEV_PIN_SET, 1,
			[dpll.h has dpll_netdev_pin_set])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netdev_dpll_pin_set])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <linux/netdevice.h>
	],[
		netdev_dpll_pin_set(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_DPLL_PIN_SET, 1,
			[netdevice.h has netdev_dpll_pin_set])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if __free anotation for kvfree could be used])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mm.h>       // Provides kvfree() function
		#include <linux/compiler.h> // Provides __free() annotation
	],[
		void *rpc_alloc __free(kvfree) = NULL;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_CAN_USE_KVFREE_CLEANUP_NO_WRAPPER, 1,
			[__free anotation for kvfree could be used])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if kvfree prototype is in slab.h])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/slab.h>
	],[
		kvfree(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_KVFREE_IN_SLAB_H, 1,
			[kvfree prototype is in slab.h])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if have hmm_pfn_to_map_order])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <linux/hmm.h>
	],[
		unsigned int i = hmm_pfn_to_map_order(0UL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_HMM_PFN_TO_MAP_ORDER, 1,
			[have hmm_pfn_to_map_order])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if vm_flags_clear exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <linux/hmm.h>
	],[
		vm_flags_clear(NULL, 0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VM_FLAGS_CLEAR, 1,
			[vm_flags_clear exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if hmm_range has hmm_pfns])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <linux/hmm.h>
	],[
		struct hmm_range h;
		h.hmm_pfns = NULL;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_HMM_RANGE_HAS_HMM_PFNS, 1,
			[hmm_range has hmm_pfns])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if hmm_range_fault has one param])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <linux/hmm.h>
	],[
		int l;
		l = hmm_range_fault(NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_HMM_RANGE_FAULT_HAS_ONE_PARAM, 1,
			[hmm_range_fault has one param])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if rdma/ib_umem.h ib_umem_dmabuf_get_pinned defined])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <rdma/ib_umem.h>
	],[
		ib_umem_dmabuf_get_pinned(NULL, 0, 0, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IB_UMEM_DMABUF_GET_PINNED, 1,
			[rdma/ib_umem.h ib_umem_dmabuf_get_pinned defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if has is_tcf_police])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <net/tc_act/tc_police.h>
	],[
		return is_tcf_police(NULL) ? 1 : 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IS_TCF_POLICE, 1,
			[is_tcf_police is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if udp_tunnel.h has enum UDP_TUNNEL_NIC_INFO_STATIC_IANA_VXLAN])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <net/udp_tunnel.h>
	],[
		int flag;

		flag = UDP_TUNNEL_NIC_INFO_STATIC_IANA_VXLAN;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_UDP_TUNNEL_NIC_INFO_STATIC_IANA_VXLAN, 1,
			[udp_tunnel.h has enum UDP_TUNNEL_NIC_INFO_STATIC_IANA_VXLAN])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if udp_tunnel.h has struct udp_tunnel_nic_info])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <net/udp_tunnel.h>
	],[
		struct udp_tunnel_nic_info x;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_UDP_TUNNEL_NIC_INFO, 1,
			[udp_tunnel.h has struct udp_tunnel_nic_info is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/netdevice.h has netdev_hold and netdev_put])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <linux/netdevice.h>
	],[
		netdev_hold(NULL,NULL, 0);
		netdev_put(NULL,NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_PUT_AND_HOLD, 1,
			[linux/netdevice.h has netdev_hold])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/netdevice.h has unregister_netdevice_notifier_net])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <linux/netdevice.h>
	],[
		unregister_netdevice_notifier_net(NULL,NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_UNREGISTER_NETDEVICE_NOTIFIER_NET, 1,
			[unregister_netdevice_notifier_net is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/netdevice.h has register_netdevice_notifier_dev_net])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <linux/netdevice.h>
	],[
		register_netdevice_notifier_dev_net(NULL,NULL,NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_REGISTER_NETDEVICE_NOTIFIER_DEV_NET, 1,
			[register_netdevice_notifier_dev_net is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/netdevice.h has dev_xdp_prog_id])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <linux/netdevice.h>
	],[
		dev_xdp_prog_id(NULL,0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEV_XDP_PROG_ID, 1,
			[dev_xdp_prog_id is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct netdev_net_notifier exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <linux/netdevice.h>
	],[
		struct netdev_net_notifier notifier;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_NET_NOTIFIER, 1,
			[struct netdev_net_notifier is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/netdevice.h has net_prefetch])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <linux/netdevice.h>
	],[
		net_prefetch(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NET_PREFETCH, 1,
			[net_prefetch is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/mm.h has is_cow_mapping])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mm.h>
	],[
		is_cow_mapping(0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IS_COW_MAPPING, 1,
			[is_cow_mapping is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/mm.h has get_user_pages_longterm])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mm.h>
	],[
		get_user_pages_longterm(0, 0, 0, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_USER_PAGES_LONGTERM, 1,
			[get_user_pages_longterm is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if get_user_pages has 4 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mm.h>
	],[
		get_user_pages(0, 0, 0, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_USER_PAGES_4_PARAMS, 1,
			[get_user_pages has 4 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if get_user_pages has 5 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mm.h>
	],[
		get_user_pages(0, 0, 0, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_USER_PAGES_5_PARAMS, 1,
			[get_user_pages has 5 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if get_user_pages has 7 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mm.h>
	],[
		get_user_pages(NULL, NULL, 0, 0, 0, NULL, NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_USER_PAGES_7_PARAMS, 1,
			[get_user_pages has 7 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if map_lock has mmap_read_lock])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <linux/mm.h>
	],[
		mmap_read_lock(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_MMAP_READ_LOCK, 1,
			[map_lock has mmap_read_lock])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if mm has get_user_pages_remote with 7 parameters and parameter 2 is integer])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <linux/mm.h>
	],[
		get_user_pages_remote(NULL, 0, 0, 0, NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_USER_PAGES_REMOTE_7_PARAMS_AND_SECOND_INT, 1,
			[get_user_pages_remote is defined with 7 parameters and parameter 2 is integer])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if mm has get_user_pages_remote with 8 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <linux/mm.h>
	],[
		get_user_pages_remote(NULL, NULL, 0, 0, 0, 0, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_USER_PAGES_REMOTE_8_PARAMS, 1,
			[get_user_pages_remote is defined with 8 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if mm has get_user_pages_remote with 8 parameters with locked])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <linux/mm.h>
	],[
		get_user_pages_remote(NULL, NULL, 0, 0, 0, NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_USER_PAGES_REMOTE_8_PARAMS_W_LOCKED, 1,
			[get_user_pages_remote is defined with 8 parameters with locked])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if kernel.h has int_pow])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/kernel.h>
	],[
		return int_pow(2, 3);

	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_INT_POW, 1,
			  [int_pow defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if prandom.h has get_random_u32_inclusive])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/random.h>
	],[
		int a;
		a = get_random_u32_inclusive(0, 100);

	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_RANDOM_U32_INCLUSIVE, 1,
			  [get_random_u32_inclusive defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if random.h has get_random_u8])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/random.h>
	],[
		int a;
		a = get_random_u8();

	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_RANDOM_U8, 1,
			  [get_random_u8 defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops has ndo_get_devlink_port])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device_ops ndops = {
			.ndo_get_devlink_port = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_GET_DEVLINK_PORT, 1,
			  [ndo_get_devlink_port is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink_fmsg_u8_pair_put returns int])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		int err = devlink_fmsg_u8_pair_put(NULL, "test", 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_INT_DEVLINK_FMSG_U8_PAIR, 1,
			  [devlink_fmsg_u8_pair_put returns int])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct devlink_port_ops had port_fn_ipsec_crypto_get])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		struct devlink_port_ops dl_port_ops  = {
			.port_fn_ipsec_crypto_get = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_IPSEC_CRYPTO, 1,
			  [port_fn_ipsec_crypto_get is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct devlink_port_ops had port_fn_ipsec_packet_get])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		struct devlink_port_ops dl_port_ops  = {
			.port_fn_ipsec_packet_get = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_IPSEC_PACKET, 1,
			  [port_fn_ipsec_packet_get is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if kernel supports v6.7 devlink instances relationships exposure])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		struct devlink_port dp;
		enum devlink_port_function_attr attr;

		dp.rel_index = 2;
		attr = DEVLINK_PORT_FN_ATTR_DEVLINK;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_INSTANCES_RELATIONSHIPS_EXPOSURE, 1,
			  [kernel supports v6.7 devlink instances relationships exposure])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device has devlink_port member])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device nd = {
			.devlink_port = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NET_DEVICE_DEVLINK_PORT, 1,
			  [struct net_device has devlink_port member])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device has xdp_metadata_ops member])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device nd = {
			.xdp_metadata_ops = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XDP_METADATA_OPS, 1,
			  [struct net_device has struct net_device has xdp_metadata_ops member])
	],[
		AC_MSG_RESULT(no)
	])

       AC_MSG_CHECKING([if kernel supports queue and napi association])
       MLNX_BG_LB_LINUX_TRY_COMPILE([
               #include <net/netdev_rx_queue.h>
       ],[
               struct napi_struct ns;
               struct netdev_rx_queue nrq;

               ns.irq = 2;
               nrq.napi = NULL;

               return 0;
       ],[
               AC_MSG_RESULT(yes)
               MLNX_AC_DEFINE(HAVE_QUEUE_AND_NAPI_ASSOCIATION, 1,
                         [kernel supports queue and napi association])
       ],[
               AC_MSG_RESULT(no)
       ])

	AC_MSG_CHECKING([if devlink.h devl_rate_leaf_create get 3 param])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devl_rate_leaf_create(NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVL_RATE_LEAF_CREATE_GET_3_PARAMS, 1,
			[devl_rate_leaf_create 3 param])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink has devlink_info_version_fixed_put])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_info_version_fixed_put(NULL, NULL, NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_INFO_VERSION_FIXED_PUT, 1,
			  [devlink_info_version_fixed_put exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink.h devlink_port_type_eth_set get 1 param])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_port_type_eth_set(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_PORT_TYPE_ETH_SET_GET_1_PARAM, 1,
			[devlink_port_type_eth_set get 1 param])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink.h has devl_param_driverinit_value_get])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devl_param_driverinit_value_get(NULL, 0, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVL_PARAM_DRIVERINIT_VALUE_GET, 1,
			[devlink.h has devl_param_driverinit_value_get])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink.h has devl_port_health_reporter_create])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devl_port_health_reporter_create(NULL, NULL, 0, NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVL_PORT_HEALTH_REPORTER_CREATE, 1,
			[devlink.h has devl_port_health_reporter_create])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink.h has devl_health_reporter_create])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devl_health_reporter_create(NULL, NULL, 0, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVL_HEALTH_REPORTER_CREATE, 1,
			[devlink.h has devl_health_reporter_create])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink.h has devlink_info_driver_name_put])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_info_driver_name_put(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_INFO_DRIVER_NAME_PUT, 1,
			[devlink.h has devlink_info_driver_name_put])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink.h has devlink_set_features])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_set_features(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_SET_FEATURES, 1,
			[devlink.h has devlink_set_features])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink.h has devlink_to_dev])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_to_dev(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_TO_DEV, 1,
			[devlink.h has devlink_to_dev])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink.h devl_port_register defined])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devl_port_register(NULL, NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVL_PORT_REGISTER, 1,
			[devlink.h devl_port_register defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink.h devl_trap_groups_register defined])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devl_trap_groups_register(NULL, NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVL_TRAP_GROUPS_REGISTER, 1,
			[devlink.h devl_trap_groups_register defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink.h devlink_param_register defined])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_param_register(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_PARAM_REGISTER, 1,
			[devlink.h devlink_param_register defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink.h has devlink_register get 1 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_register(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_REGISTER_GET_1_PARAMS, 1,
			[devlink.h has devlink_register get 1 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink.h has devl_register])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devl_register(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVL_REGISTER, 1,
			[devlink.h has devl_register])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink.h has devl_resource_register])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devl_resource_register(NULL, NULL, 0, 0, 0, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVL_RESOURCE_REGISTER, 1,
			[devlink.h has devl_resource_register])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink.h has devl_resources_unregister])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devl_resources_unregister(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVL_RESOURCES_UNREGISTER, 1,
			[devlink.h has devl_resources_unregister])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink.h has devlink_resources_unregister 2 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_resources_unregister(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_RESOURCES_UNREGISTER_2_PARAMS, 1,
			[devlink.h has devlink_resources_unregister 2 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink.h has devlink_resources_unregister 1 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_resources_unregister(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_RESOURCES_UNREGISTER_1_PARAMS, 1,
			[devlink.h has devlink_resources_unregister 1 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink.h has devlink_alloc get 3 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_alloc(NULL, 0, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_ALLOC_GET_3_PARAMS, 1,
			[devlink.h has devlink_alloc get 3 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink.h has devlink_port_attrs_pci_sf_set get 4 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_port_attrs_pci_sf_set(NULL, 0, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_PORT_ATTRS_PCI_SF_SET_GET_4_PARAMS, 1,
			[devlink.h has devlink_port_attrs_pci_sf_set get 4 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink.h has devlink_port_attrs_pci_sf_set get 5 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_port_attrs_pci_sf_set(NULL, 0, 0, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_PORT_ATTRS_PCI_SF_SET_GET_5_PARAMS, 1,
			[devlink.h has devlink_port_attrs_pci_sf_set get 5 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink.h devlink_port_attrs_pci_vf_set get 3 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_port_attrs_pci_vf_set(NULL, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_PORT_ATTRS_PCI_VF_SET_GET_3_PARAMS, 1,
			  [devlink.h devlink_port_attrs_pci_vf_set get 3 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink has devlink_port_attrs_pci_vf_set has 5 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_port_attrs_pci_vf_set(NULL, NULL, 0, 0, 0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_PORT_ATTRS_PCI_VF_SET_GET_5_PARAMS, 1,
			  [devlink_port_attrs_pci_vf_set has 5 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink has devlink_port_attrs_pci_vf_set has 5 params and controller num])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_port_attrs_pci_vf_set(NULL, 1, 0, 0, 0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_PORT_ATTRS_PCI_VF_SET_GET_CONTROLLER_NUM, 1,
			 [devlink_port_attrs_pci_vf_set has 5 params and controller num])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink.h devlink_port_attrs_pci_pf_set get 2 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_port_attrs_pci_pf_set(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_PORT_ATTRS_PCI_PF_SET_GET_2_PARAMS, 1,
			  [devlink.h devlink_port_attrs_pci_pf_set get 2 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink.h has devlink_fmsg_binary_pair_nest_start])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_fmsg_binary_pair_nest_start(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_FMSG_BINARY_PAIR_NEST_START, 1,
			  [devlink.h has devlink_fmsg_binary_pair_nest_start is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink has devlink_flash_update_status_notify])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_flash_update_status_notify(NULL, NULL, NULL, 0, 0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_FLASH_UPDATE_STATUS_NOTIFY, 1,
			  [devlink_flash_update_status_notify])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink has devlink_flash_update_end_notify])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_flash_update_end_notify(NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_FLASH_UPDATE_END_NOTIFY, 1,
			  [devlink_flash_update_end_notify])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink has devlink_port_type_eth_set])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_port_type_eth_set(NULL, NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_PORT_TYPE_ETH_SET_GET_2_PARAM, 1,
			  [devlink_port_type_eth_set exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink has devlink_health_reporter_state_update])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_health_reporter_state_update(NULL, 0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_HEALTH_REPORTER_STATE_UPDATE, 1,
			  [devlink_health_reporter_state_update exist])
	],[
		AC_MSG_RESULT(no)
	])

        AC_MSG_CHECKING([if devlink_health_reporter_ops.recover has extack parameter])
        MLNX_BG_LB_LINUX_TRY_COMPILE([
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
		}
        ],[
                AC_MSG_RESULT(yes)
                MLNX_AC_DEFINE(HAVE_HEALTH_REPORTER_RECOVER_HAS_EXTACK, 1,
                          [devlink_health_reporter_ops.recover has extack])
        ],[
                AC_MSG_RESULT(no)
        ])

        AC_MSG_CHECKING([if struct devlink_param set function pointer has extack parameter])
        MLNX_BG_LB_LINUX_TRY_COMPILE([
                #include <net/devlink.h>
		static int param_set(struct devlink *devlink,
				     u32 id,
			             struct devlink_param_gset_ctx *ctx,
			             struct netlink_ext_ack *extack);
	],[
		struct devlink_param dp = {
			.set = param_set,
		};
        ],[
                AC_MSG_RESULT(yes)
                MLNX_AC_DEFINE(HAVE_DEVLINK_PARAM_SET_FUNCTION_POINTER_HAS_EXTACK, 1,
                          [struct devlink_param set function pointer has extack parameter])
        ],[
                AC_MSG_RESULT(no)
        ])

	AC_MSG_CHECKING([if devlink has devlink_param_driverinit_value_get])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_param_driverinit_value_get(NULL, 0, NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_DRIVERINIT_VAL, 1,
			  [devlink_param_driverinit_value_get exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink enum has DEVLINK_PARAM_GENERIC_ID_IO_EQ_SIZE])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		int i = DEVLINK_PARAM_GENERIC_ID_IO_EQ_SIZE;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_PARAM_GENERIC_ID_IO_EQ_SIZE, 1,
			  [devlink enum has DEVLINK_PARAM_GENERIC_ID_IO_EQ_SIZE])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink enum has HAVE_DEVLINK_PARAM_GENERIC_ID_ENABLE_ETH])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		int i = DEVLINK_PARAM_GENERIC_ID_ENABLE_ETH;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_PARAM_GENERIC_ID_ENABLE_ETH, 1,
			  [devlink enum has HAVE_DEVLINK_PARAM_GENERIC_ID_ENABLE_ETH])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink struct devlink_port_new_attrs exist])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		struct devlink_port_new_attrs i;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_PORT_NEW_ATTRS_STRUCT, 1,
			  [devlink struct devlink_port_new_attrs exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink_port_attrs_set has 7 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_port_attrs_set(NULL, 0, 0, 0, 0, NULL ,0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_PORT_ATRRS_SET_GET_7_PARAMS, 1,
			  [devlink_port_attrs_set has 7 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink_port_attrs_set has 5 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_port_attrs_set(NULL, 0, 0, 0, 0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_PORT_ATRRS_SET_GET_5_PARAMS, 1,
			  [devlink_port_attrs_set has 5 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink_port_attrs_set has 2 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_port_attrs_set(NULL, 0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_PORT_ATRRS_SET_GET_2_PARAMS, 1,
			  [devlink_port_attrs_set has 2 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink enum has DEVLINK_PARAM_GENERIC_ID_ENABLE_ROCE])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		int i = DEVLINK_PARAM_GENERIC_ID_ENABLE_ROCE;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_PARAM_GENERIC_ID_ENABLE_ROCE, 1,
			  [struct devlink_param exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink enum has DEVLINK_PARAM_GENERIC_ID_ENABLE_REMOTE_DEV_RESET])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		int i = DEVLINK_PARAM_GENERIC_ID_ENABLE_REMOTE_DEV_RESET;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_PARAM_GENERIC_ID_ENABLE_REMOTE_DEV_RESET, 1,
			  [enum DEVLINK_PARAM_GENERIC_ID_ENABLE_REMOTE_DEV_RESET exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink enum devlink_port_fn_state exist])
        MLNX_BG_LB_LINUX_TRY_COMPILE([
                #include <uapi/linux/devlink.h>
        ],[
                enum devlink_port_fn_state fn_state;
                return 0;
        ],[
                AC_MSG_RESULT(yes)
                MLNX_AC_DEFINE(HAVE_DEVLINK_PORT_FN_STATE, 1,
                          [enum devlink_port_fn_state exist])
        ],[
                AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink enum devlink_port_fn_opstate exist])
        MLNX_BG_LB_LINUX_TRY_COMPILE([
                #include <uapi/linux/devlink.h>
        ],[
                enum devlink_port_fn_opstate fn_opstate;
                return 0;
        ],[
                AC_MSG_RESULT(yes)
                MLNX_AC_DEFINE(HAVE_DEVLINK_PORT_FN_OPSTATE, 1,
                          [enum devlink_port_fn_opstate exist])
        ],[
                AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink enum has DEVLINK_PORT_FLAVOUR_VIRTUAL])
        MLNX_BG_LB_LINUX_TRY_COMPILE([
                #include <uapi/linux/devlink.h>
        ],[
                int i = DEVLINK_PORT_FLAVOUR_VIRTUAL;
                return 0;
        ],[
                AC_MSG_RESULT(yes)
                MLNX_AC_DEFINE(HAVE_DEVLINK_PORT_FLAVOUR_VIRTUAL, 1,
                          [enum DEVLINK_PORT_FLAVOUR_VIRTUAL is defined])
        ],[
                AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink enum has DEVLINK_PORT_FLAVOUR_PCI_SF])
        MLNX_BG_LB_LINUX_TRY_COMPILE([
                #include <uapi/linux/devlink.h>
        ],[
                int i = DEVLINK_PORT_FLAVOUR_PCI_SF;
                return 0;
        ],[
                AC_MSG_RESULT(yes)
                MLNX_AC_DEFINE(HAVE_DEVLINK_PORT_FLAVOUR_PCI_SF, 1,
                          [enum DEVLINK_PORT_FLAVOUR_PCI_SF is defined])
        ],[
                AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink has devlink_reload_disable])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_reload_disable(NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_RELOAD_DISABLE, 1,
			  [devlink_reload_disable exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink has devlink_reload_enable])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_reload_enable(NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_RELOAD_ENABLE, 1,
			  [devlink_reload_enable exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink has devlink_net])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_net(NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_NET, 1,
			  [devlink_net exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct devlink_ops has reload has 2 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
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
	],[
	        AC_MSG_RESULT(yes)
	        MLNX_AC_DEFINE(HAVE_DEVLINK_HAS_RELOAD, 1,
	                  [reload is defined])
	],[
	        AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct devlink_ops has reload_up/down])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		struct devlink_ops dlops = {
			.reload_up = NULL,
			.reload_down = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_HAS_RELOAD_UP_DOWN, 1,
			  [reload_up/down is defined])
	],[
		AC_MSG_RESULT(no)
	])

        AC_MSG_CHECKING([if devlink_ops.port_function_hw_addr_get has 4 params])
        MLNX_BG_LB_LINUX_TRY_COMPILE([
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
        ],[
                AC_MSG_RESULT(yes)
                MLNX_AC_DEFINE(HAVE_PORT_FUNCTION_HW_ADDR_GET_GET_4_PARAM, 1,
                          [port_function_hw_addr_get has 4 params])
        ],[
                AC_MSG_RESULT(no)
        ])

        AC_MSG_CHECKING([if devlink_ops.port_function_state_get has 4 params])
        MLNX_BG_LB_LINUX_TRY_COMPILE([
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
        ],[
                AC_MSG_RESULT(yes)
                MLNX_AC_DEFINE(HAVE_PORT_FUNCTION_STATE_GET_4_PARAM, 1,
                          [port_function_state_get has 4 params])
        ],[
                AC_MSG_RESULT(no)
        ])

       AC_MSG_CHECKING([if struct devlink_ops has port_function_state_get/set])
       MLNX_BG_LB_LINUX_TRY_COMPILE([
               #include <net/devlink.h>
       ],[
               struct devlink_ops dlops = {
                       .port_fn_state_get = NULL,
                       .port_fn_state_set = NULL,
               };

               return 0;
       ],[
               AC_MSG_RESULT(yes)
               MLNX_AC_DEFINE(HAVE_DEVLINK_HAS_PORT_FUNCTION_STATE_GET, 1,
                         [port_function_state_get/set is defined])
       ],[
               AC_MSG_RESULT(no)
       ])

        AC_MSG_CHECKING([if devlink_ops.reload_down has 3 params])
        MLNX_BG_LB_LINUX_TRY_COMPILE([
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
        ],[
                AC_MSG_RESULT(yes)
                MLNX_AC_DEFINE(HAVE_DEVLINK_RELOAD_DOWN_HAS_3_PARAMS, 1,
                          [reload_down has 3 params])
        ],[
                AC_MSG_RESULT(no)
        ])

	AC_MSG_CHECKING([if devlink_ops.reload_down has 5 params])
        MLNX_BG_LB_LINUX_TRY_COMPILE([
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
        ],[
                AC_MSG_RESULT(yes)
                MLNX_AC_DEFINE(HAVE_DEVLINK_RELOAD_DOWN_SUPPORT_RELOAD_ACTION, 1,
                          [reload_down has 5 params])
        ],[
                AC_MSG_RESULT(no)
        ])

	AC_MSG_CHECKING([if struct devlink_port_ops exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		struct devlink_port_ops dlops = {
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_PORT_OPS, 1,
			  [struct devlink_port_ops exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct devlink_ops has info_get])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		struct devlink_ops dlops = {
			.info_get = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_HAS_INFO_GET, 1,
			  [info_get is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink struct devlink_trap exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		struct devlink_trap t;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_TRAP_SUPPORT, 1,
			[devlink struct devlink_trap exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink has DEVLINK_TRAP_GENERIC_ID_DMAC_FILTER])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		int n = DEVLINK_TRAP_GENERIC_ID_DMAC_FILTER;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_TRAP_DMAC_FILTER, 1,
			[devlink has DEVLINK_TRAP_GENERIC_ID_DMAC_FILTER])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink_ops.trap_action_set has 4 args])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
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
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_TRAP_ACTION_SET_4_ARGS, 1,
			[devlink_ops.trap_action_set has 4 args])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink_trap_report has 5 args])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_trap_report(NULL, NULL, NULL, NULL, NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_TRAP_REPORT_5_ARGS, 1,
			[devlink_trap_report has 5 args])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink has DEVLINK_TRAP_GROUP_GENERIC with 2 args])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		static const struct devlink_trap_group mlx5_trap_groups_arr[] = {
			DEVLINK_TRAP_GROUP_GENERIC(L2_DROPS, 0),
		};
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_TRAP_GROUP_GENERIC_2_ARGS, 1,
			[devlink has DEVLINK_TRAP_GROUP_GENERIC with 2 args])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink has devlink_trap_groups_register])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_trap_groups_register(NULL, NULL, 0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_TRAP_GROUPS_REGISTER, 1,
			[devlink has devlink_trap_groups_register])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink has devlink_port_health_reporter_create])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		struct devlink_health_reporter *r;

		r = devlink_port_health_reporter_create(NULL, NULL, 0, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_PORT_HEALTH_REPORTER_CREATE, 1,
			[devlink_health_reporter_create is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink has devlink_port_health_reporter_destroy])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_port_health_reporter_destroy(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_PORT_HEALTH_REPORTER_DESTROY, 1,
			[devlink_port_health_reporter_destroy is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink has devlink_health_reporter_create with 5 args])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		struct devlink_health_reporter *r;

		r = devlink_health_reporter_create(NULL, NULL, 0, 0, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_HEALTH_REPORTER_CREATE_5_ARGS, 1,
			[devlink_health_reporter_create has 5 args])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink has devlink_health_reporter_create with 4 args])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		struct devlink_health_reporter *r;

		r = devlink_health_reporter_create(NULL, NULL, 0, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_HEALTH_REPORTER_CREATE_4_ARGS, 1,
			[devlink_health_reporter_create has 4 args])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink has devlink_health_reporter & devlink_fmsg])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
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
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_HEALTH_REPORT_BASE_SUPPORT, 1,
			  [structs devlink_health_reporter & devlink_fmsg exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink has devlink_fmsg_binary_put])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		struct devlink_fmsg *fmsg;
		int err;
		int value;

		err =  devlink_fmsg_binary_put(fmsg, &value, 2);
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_FMSG_BINARY_PUT, 1,
				[devlink_fmsg_binary_put exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink has devlink_fmsg_binary_pair_put])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
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
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_FMSG_BINARY_PAIR_PUT_ARG_U32_RETURN_INT, 1,
			  [devlink_fmsg_binary_pair_put exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink has devlink_fmsg_binary_pair_put])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>

		/* Only interested in function with arg u32 and not u16 */
		/* See upstream commit e2cde864a1d3e3626bfc8fa088fbc82b04ce66ed */
		void devlink_fmsg_binary_pair_put(struct devlink_fmsg *fmsg, const char *name, const void *value, u32 value_len);
	],[
		struct devlink_fmsg *fmsg;
		int value;

		devlink_fmsg_binary_pair_put(fmsg, "name", &value, 2);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_FMSG_BINARY_PAIR_PUT_ARG_U32_RETURN_VOID, 1,
			  [devlink_fmsg_binary_pair_put exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct devlink_ops.eswitch_mode_set has extack])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
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
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_ESWITCH_MODE_SET_EXTACK, 1,
			  [struct devlink_ops.eswitch_mode_set has extack])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct devlink_ops has port_function_roce/mig_get/set])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		struct devlink_ops dlops = {
			.port_fn_migratable_get = NULL,
			.port_fn_migratable_set = NULL,
			.port_fn_roce_get = NULL,
			.port_fn_roce_set = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_HAS_PORT_FN_ROCE_MIG, 1,
			  [port_function_roce/mig_get/set is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct devlink_ops has port_function_hw_addr_get/set])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		struct devlink_ops dlops = {
			.port_function_hw_addr_get = NULL,
			.port_function_hw_addr_set = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_HAS_PORT_FUNCTION_HW_ADDR_GET, 1,
			  [port_function_hw_addr_get/set is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct devlink_ops has rate functions])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		struct devlink_ops dlops = {
			.rate_leaf_tx_share_set = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_HAS_RATE_FUNCTIONS, 1,
			  [rate functions are defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct devlink_ops defines eswitch_encap_mode_set/get with enum arg])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
		#include <uapi/linux/devlink.h>
	],[
		int local_eswitch_encap_mode_get(struct devlink *devlink,
					      enum devlink_eswitch_encap_mode *p_encap_mode) {
			return 0;
		}
		int local_eswitch_encap_mode_set(struct devlink *devlink,
					      enum devlink_eswitch_encap_mode encap_mode,
					      struct netlink_ext_ack *extack) {
			return 0;
		}

		struct devlink_ops dlops = {
			.eswitch_encap_mode_set = local_eswitch_encap_mode_set,
			.eswitch_encap_mode_get = local_eswitch_encap_mode_get,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_HAS_ESWITCH_ENCAP_MODE_SET_GET_WITH_ENUM, 1,
			  [eswitch_encap_mode_set/get is defined with enum])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct devlink_ops has flash_update])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		struct devlink_ops dlops = {
			.flash_update = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_HAS_FLASH_UPDATE, 1,
			  [flash_update is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct devlink_ops flash_update get 3 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
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
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLASH_UPDATE_GET_3_PARAMS, 1,
			  [struct devlink_ops flash_update get 3 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink has devlink_port_attrs_pci_pf_set has 4 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_port_attrs_pci_pf_set(NULL, NULL, 0, 0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_PORT_ATTRS_PCI_PF_SET_4_PARAMS, 1,
			  [devlink_port_attrs_pci_pf_set has 4 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink has devlink_port_attrs_pci_pf_set has 4 params and controller num])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_port_attrs_pci_pf_set(NULL, 1, 0, 0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_PORT_ATTRS_PCI_PF_SET_CONTROLLER_NUM, 1,
			  [devlink_port_attrs_pci_pf_set has 4 params and controller num])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink has devlink_port_attrs_pci_pf_set has 2 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_port_attrs_pci_pf_set(NULL, 0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_PORT_ATTRS_PCI_PF_SET_2_PARAMS, 1,
			  [devlink_port_attrs_pci_pf_set has 2 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devlink_flash_update_params has struct firmware fw])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		struct devlink_flash_update_params *x;
		x->fw = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_FLASH_UPDATE_PARAMS_HAS_STRUCT_FW, 1,
			  [devlink_flash_update_params has struct firmware fw])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if exists netif_carrier_event])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netif_carrier_event(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_CARRIER_EVENT, 1,
			  [netif_carrier_event exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netif_device_present get const])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		const struct net_device *dev;
		netif_device_present(dev);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_DEVICE_PRESENT_GET_CONST, 1,
			  [netif_device_present get const])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct devlink_port has attrs.switch_port])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		struct devlink_port *port;

		port->attrs.switch_port = true;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_PORT_HAS_SWITCH_PORT, 1,
			  [struct devlink_port has attrs.switch_port])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct devlink_port has attrs.switch_id])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		struct devlink_port *port;

		port->attrs.switch_id.id_len = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_PORT_HAS_SWITCH_ID, 1,
			  [struct devlink_port has attrs.switch_id])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device has devlink_port])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device *dev;

		dev->devlink_port = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NET_DEVICE_HAS_DEVLINK_PORT, 1,
			  [struct net_device has devlink_port])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device has lower_level])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device dev;

		dev.lower_level = 1;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NET_DEVICE_LOWER_LEVEL, 1,
			  [struct net_device has lower_level])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdev_lag_hash has NETDEV_LAG_HASH_VLAN_SRCMAC])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		int x = NETDEV_LAG_HASH_VLAN_SRCMAC;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_LAG_HASH_VLAN_SRCMAC, 1,
			  [netdev_lag_hash has NETDEV_LAG_HASH_VLAN_SRCMAC])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ethtool_link_ksettings has lanes])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
                struct ethtool_link_ksettings x = {
			.lanes = 0,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ETHTOOL_LINK_KSETTINGS_HAS_LANES, 1,
			  [ethtool_link_ksettings has lanes])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ethtool.h kernel_ethtool_ringparam has tcp_data_split member])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
                struct kernel_ethtool_ringparam x = {
			.tcp_data_split = 0,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_KERNEL_RINGPARAM_TCP_DATA_SPLIT, 1,
			  [ethtool.h kernel_ethtool_ringparam has tcp_data_split member])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ethtool.h has struct kernel_ethtool_ringparam])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
                struct kernel_ethtool_ringparam x;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_STRUCT_KERNEL_ETHTOOL_RINGPARAM, 1,
			  [ethtool.h has struct kernel_ethtool_ringparam])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ethtool.h has struct kernel_ethtool_ts_info])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
                struct kernel_ethtool_ts_info x;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_STRUCT_KERNEL_ETHTOOL_TS_INFO, 1,
			  [ethtool.h has struct kernel_ethtool_ts_info])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops has supported_coalesce_params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.supported_coalesce_params = 0,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SUPPORTED_COALESCE_PARAM, 1,
			  [supported_coalesce_params is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops has get_module_eeprom_by_page])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.get_module_eeprom_by_page = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_MODULE_EEPROM_BY_PAGE, 1,
			[ethtool_ops has get_module_eeprom_by_page])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/tls.h has tls_is_skb_tx_device_offloaded])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/tls.h>
	],[
		tls_is_skb_tx_device_offloaded(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TLS_IS_SKB_TX_DEVICE_OFFLOADED, 1,
			  [net/tls.h has tls_is_skb_tx_device_offloaded])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/tls.h has struct tls_offload_resync_async])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/tls.h>
	],[
		struct tls_offload_resync_async	x;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TLS_OFFLOAD_RESYNC_ASYNC_STRUCT, 1,
			  [net/tls.h has struct tls_offload_resync_async is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ktls related structs exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
		#include <net/tls.h>
	],[
		struct tlsdev_ops dev;
		struct tls_offload_context_tx tx_ctx;
		struct tls12_crypto_info_aes_gcm_128 crypto_info;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_KTLS_STRUCTS, 1,
			  [ktls related structs exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct tlsdev_ops has tls_dev_resync])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/tls.h>
	],[
		struct tlsdev_ops dev;

		dev.tls_dev_resync = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TLSDEV_OPS_HAS_TLS_DEV_RESYNC, 1,
			  [struct tlsdev_ops has tls_dev_resync])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/skbuff.h skb_frag_fill_page_desc exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		skb_frag_fill_page_desc(NULL, NULL, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SKB_FRAG_FILL_PAGE_DESC, 1,
			  [linux/skbuff.h skb_frag_fill_page_desc is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/skbuff.h napi_build_skb exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		napi_build_skb(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NAPI_BUILD_SKB, 1,
			  [linux/skbuff.h napi_build_skb is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if skb_frag_off_add exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		skb_frag_off_add(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SKB_FRAG_OFF_ADD, 1,
			  [linux/skbuff.h skb_frag_off_add is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if skb_frag_off_set exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		skb_frag_off_set(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SKB_FRAG_OFF_SET, 1,
			  [linux/skbuff.h skb_frag_off_set is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if napi_reschedule exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		int ret;

		ret = napi_reschedule(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NAPI_RESCHEDULE, 1,
			  [napi_reschedule exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device has netns_local as member])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device netdev = {
			.netns_local = 0,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_NETNS_LOCAL, 1,
			  [struct net_device has netns_local as member])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device has devlink_port as member])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device netdev = {
			.devlink_port = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_DEVLINK_PORT, 1,
			  [struct net_device has devlink_port as member])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct devlink_port_osp has del_port as cb])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		static const struct devlink_port_ops ops= {
			.port_del = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_PORT_DEL_IN_DEVLINK_PORT, 1,
			  [struct ndevlink_port_ops has devlink_port as member])
	],[
		AC_MSG_RESULT(no)
	])


	AC_MSG_CHECKING([if struct net_device_ops has ndo_xsk_wakeup])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device_ops netdev_ops = {
			.ndo_xsk_wakeup = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_XSK_WAKEUP, 1,
			  [ndo_xsk_wakeup is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if enum tc_htb_command exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/pkt_cls.h>
	],[
		enum tc_htb_command x;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ENUM_TC_HTB_COMMAND, 1,
			  [enum tc_htb_command is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct tc_htb_qopt_offload has prio])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/pkt_cls.h>
	],[
		struct tc_htb_qopt_offload x;

		x.prio = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TC_HTB_OPT_PRIO, 1,
			  [tc_htb_qopt_offload has prio])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct tc_htb_qopt_offload has quantum])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/pkt_cls.h>
	],[
		struct tc_htb_qopt_offload x;

		x.quantum = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TC_HTB_OPT_QUANTUM, 1,
			  [tc_htb_qopt_offload has quantum])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct tc_cls_flower_offload exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/pkt_cls.h>
	],[
		struct tc_cls_flower_offload x;
		x = x;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TC_FLOWER_OFFLOAD, 1,
			  [struct tc_cls_flower_offload is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct tc_block_offload exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/pkt_cls.h>
	],[
		struct tc_block_offload x;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TC_BLOCK_OFFLOAD, 1,
			  [struct tc_block_offload is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct flow_block_offload exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/pkt_cls.h>
	],[
		struct flow_block_offload x;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_BLOCK_OFFLOAD, 1,
			  [struct flow_block_offload exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct flow_block_offload hash unlocked_driver_cb])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/pkt_cls.h>
	],[
		struct flow_block_offload x;
		x.unlocked_driver_cb = true;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_UNLOCKED_DRIVER_CB, 1,
			  [struct flow_block_offload has unlocked_driver_cb])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if NL_SET_ERR_MSG_WEAK_MOD exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netlink.h>
	],[
		struct netlink_ext_ack extack = {};

		NL_SET_ERR_MSG_WEAK_MOD(&extack, "test");
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NL_SET_ERR_MSG_WEAK_MOD, 1,
			  [NL_SET_ERR_MSG_WEAK_MOD exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if tc_cls_common_offload has extack])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/pkt_cls.h>
	],[
		struct tc_cls_common_offload x;
		x.extack = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TC_CLS_OFFLOAD_EXTACK_FIX, 1,
			  [struct tc_cls_common_offload has extack])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct tc_block_offload has extack])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/pkt_cls.h>
	],[
		struct tc_block_offload x;
		x.extack = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TC_BLOCK_OFFLOAD_EXTACK, 1,
			  [struct tc_block_offload has extack])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ptp_clock_info has gettimex64])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ptp_clock_kernel.h>
	],[
		struct ptp_clock_info info = {
			.gettimex64 = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GETTIMEX64, 1,
			  [gettimex64 is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ptp_clock_info has getmaxphase])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ptp_clock_kernel.h>
	],[
		struct ptp_clock_info info = {
			.getmaxphase = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PTP_CLOCK_INFO_NDO_GETMAXPHASE, 1,
			  [struct ptp_clock_info has getmaxphase])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ptp_clock_info has adjfreq])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ptp_clock_kernel.h>
	],[
		struct ptp_clock_info info = {
			.adjfreq = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PTP_CLOCK_INFO_NDO_ADJFREQ, 1,
			  [adjfreq is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ptp_clock_info has adjphase])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ptp_clock_kernel.h>
	],[
		struct ptp_clock_info info = {
			.adjphase = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PTP_CLOCK_INFO_ADJPHASE, 1,
			  [adjphase is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if adjust_by_scaled_ppm exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ptp_clock_kernel.h>
	],[
		adjust_by_scaled_ppm(0,0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ADJUST_BY_SCALED_PPM, 1,
			  [adjfine is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci_dev has pci_vpd_find_tag get 4 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		pci_vpd_find_tag(NULL , 0, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_VPD_FIND_TAG_GET_4_PARAM, 1,
			  [pci_dev has pci_vpd_find_tag get 4 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci_dev has pci_vpd_alloc])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		pci_vpd_alloc(NULL ,NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_VPD_ALLOC, 1,
			  [pci_dev has pci_vpd_alloc])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci_dev has link_active_reporting])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		struct pci_dev *bridge;
		bridge->link_active_reporting = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_DEV_LINK_ACTIVE_REPORTING, 1,
			  [pci_dev has link_active_reporting])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci.h has pci_iov_vf_id])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		pci_iov_vf_id(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_IOV_VF_ID, 1,
			  [pci_iov_vf_id is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci.h has pci_iov_get_pf_drvdata])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		pci_iov_get_pf_drvdata(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_IOV_GET_PF_DRVDATA, 1,
			  [pci_iov_get_pf_drvdata is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if mm.h has want_init_on_alloc])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mm.h>
	],[
		bool x = want_init_on_alloc(__GFP_ZERO);

		return 0;
	],[
	AC_MSG_RESULT(yes)
	MLNX_AC_DEFINE(HAVE_WANT_INIT_ON_ALLOC, 1,
		[want_init_on_alloc is defined])
	],[
	AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct page has dma_addr array member])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mm_types.h>
	],[
		struct page page;

		page.dma_addr[0] = 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PAGE_DMA_ADDR_ARRAY, 1,
			[struct page has dma_addr array member])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if skbuff.h has skb_frag_off])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		skb_frag_off(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SKB_FRAG_OFF, 1,
			  [skb_frag_off is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if skbuff.h has dev_page_is_reusable])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		dev_page_is_reusable(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEV_PAGE_IS_REUSABLE, 1,
			  [dev_page_is_reusable is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/pkt_cls.h has tc_skb_ext_alloc])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
		#include <net/pkt_cls.h>
	],[
		struct sk_buff skb;

		tc_skb_ext_alloc(&skb);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TC_SKB_EXT_ALLOC, 1,
			  [tc_skb_ext_alloc is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h dev_change_flags has 3 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		dev_change_flags(NULL, 0, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEV_CHANGE_FLAGS_HAS_3_PARAMS, 1,
			  [dev_change_flags has 3 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if user_access_begin has 2 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/uaccess.h>
	],[
		size_t size = 0;
		const void __user *from = NULL;

		if (!user_access_begin(from, size))
			return 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_USER_ACCESS_BEGIN_2_PARAMS, 1,
			  [user_access_begin has 2 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if user_access_begin has 3 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/uaccess.h>
	],[
		size_t size = 0;
		const void __user *from = NULL;

		if (!user_access_begin(VERIFY_READ, from, size))
			return 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_USER_ACCESS_BEGIN_3_PARAMS, 1,
			  [user_access_begin has 3 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if uaccess.h access_ok has 3 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/uaccess.h>
	],[
		access_ok(0, NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ACCESS_OK_HAS_3_PARAMS, 1,
			  [access_ok has 3 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if uaccess.h access_ok has check_zeroed_user])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/uaccess.h>
	],[
		int ret;

		ret = check_zeroed_user(NULL,0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_CHECK_ZEROED_USER, 1,
			  [access_ok has check_zeroed_user])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if mm.h put_user_pages_dirty_lock has 3 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mm.h>
	],[
		put_user_pages_dirty_lock(NULL, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PUT_USER_PAGES_DIRTY_LOCK_3_PARAMS, 1,
			  [put_user_pages_dirty_lock has 3 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if mm.h put_user_pages_dirty_lock has 2 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mm.h>
	],[
		put_user_pages_dirty_lock(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PUT_USER_PAGES_DIRTY_LOCK_2_PARAMS, 1,
			  [put_user_pages_dirty_lock has 2 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if flow_dissector.h has struct flow_dissector_mpls_lse])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_dissector.h>
	],[
		struct flow_dissector_mpls_lse ls;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_DISSECTOR_MPLS_LSE, 1,
			  [flow_dissector.h has struct flow_dissector_mpls_lse])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if enum switchdev_attr_id has SWITCHDEV_ATTR_ID_BRIDGE_VLAN_PROTOCOL])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/switchdev.h>
	],[
		enum switchdev_attr_id x = SWITCHDEV_ATTR_ID_BRIDGE_VLAN_PROTOCOL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SWITCHDEV_ATTR_ID_BRIDGE_VLAN_PROTOCOL, 1,
			  [enum switchdev_attr_id has SWITCHDEV_ATTR_ID_BRIDGE_VLAN_PROTOCOL])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if switchdev.h has struct switchdev_ops])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/switchdev.h>
		#include <linux/netdevice.h>
	],[
		struct switchdev_ops x;
		struct net_device *ndev;

		ndev->switchdev_ops = &x;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SWITCHDEV_OPS, 1,
			  [HAVE_SWITCHDEV_OPS is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct switchdev_obj_port_vlan has vid])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/switchdev.h>
	],[
		struct switchdev_obj_port_vlan x;
		x.vid = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_STRUCT_SWITCHDEV_OBJ_PORT_VLAN_VID, 1,
			  [struct switchdev_obj_port_vlan has vid])
	],[
		AC_MSG_RESULT(no)
	])
	AC_MSG_CHECKING([if struct switchdev_brport_flags exist])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/switchdev.h>
	],[
		struct switchdev_brport_flags x;
		x.mask = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_STRUCT_SWITCHDEV_BRPORT_FLAGS, 1,
			  [struct switchdev_brport_flags exist])
	],[
		AC_MSG_RESULT(no)
	])


	AC_MSG_CHECKING([if switchdev.h has switchdev_port_same_parent_id])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/switchdev.h>
	],[
		switchdev_port_same_parent_id(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SWITCHDEV_PORT_SAME_PARENT_ID, 1,
			  [switchdev_port_same_parent_id is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct sk_buff has xmit_more])
	case $LINUXRELEASE in
	3\.1[[0-7]]*fbk*|2*fbk*)
	AC_MSG_RESULT(Not checking xmit_more support for fbk kernel: $LINUXRELEASE)
	;;
	*)
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		struct sk_buff *skb;
		skb->xmit_more = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SK_BUFF_XMIT_MORE, 1,
			  [xmit_more is defined])
	],[
		AC_MSG_RESULT(no)
	])
	;;
	esac

	AC_MSG_CHECKING([if xfrm_dev_offload has flags])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xfrm.h>
	],[
		struct xfrm_dev_offload x = {
                        .flags = XFRM_DEV_OFFLOAD_FLAG_ACQ,
                };

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XFRM_DEV_OFFLOAD_FLAG_ACQ, 1,
			  [xfrm_dev_offload has flags])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if xfrm_dev_offload has real_dev as member])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xfrm.h>
	],[
		struct xfrm_dev_offload x = {
                        .real_dev = NULL,
                };

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XFRM_DEV_REAL_DEV, 1,
			  [xfrm_dev_offload has real_dev as member])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if xfrm_state_offload has dir as member])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xfrm.h>
	],[
		struct xfrm_state_offload x = {
                        .dir = 0,
                };

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XFRM_STATE_DIR, 1,
			  [xfrm_dev_offload has state as member])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if xfrm_dev_offload has dir as member])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xfrm.h>
	],[
		struct xfrm_dev_offload x = {
                        .dir = 0,
                };

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XFRM_DEV_DIR, 1,
			  [xfrm_dev_offload has dir as member])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if xfrm_dev_offload has type as member])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xfrm.h>
	],[
		struct xfrm_dev_offload x = {
                        .type = 0,
                };

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XFRM_DEV_TYPE, 1,
			  [xfrm_dev_offload has type as member])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if xfrm_state_offload has real_dev as member])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xfrm.h>
	],[
		struct xfrm_state_offload x = {
                        .real_dev = NULL,
                };

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XFRM_STATE_REAL_DEV, 1,
			  [xfrm_state_offload has real_dev as member])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if secpath_set returns struct sec_path *])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xfrm.h>
	],[
		struct sec_path *temp = secpath_set(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SECPATH_SET_RETURN_POINTER, 1,
			  [if secpath_set returns struct sec_path *])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if eth_get_headlen has 3 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/etherdevice.h>
	],[
		eth_get_headlen(NULL, NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ETH_GET_HEADLEN_3_PARAMS, 1,
			  [eth_get_headlen is defined with 3 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if eth_get_headlen has 2 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/etherdevice.h>
	],[
		eth_get_headlen(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ETH_GET_HEADLEN_2_PARAMS, 1,
			  [eth_get_headlen is defined with 2 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if if_vlan.h has vlan_get_encap_level])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/if_vlan.h>
	],[
		vlan_get_encap_level(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VLAN_GET_ENCAP_LEVEL, 1,
			  [vlan_get_encap_level is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct vlan_ethhdr has addrs member])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/if_vlan.h>
	],[
		struct vlan_ethhdr vhdr = {
			.addrs = {0},
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VLAN_ETHHDR_HAS_ADDRS, 1,
			  [struct vlan_ethhdr has addrs member])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ndo_select_queue has accel_priv])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

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
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_SELECT_QUEUE_HAS_3_PARMS_NO_FALLBACK, 1,
			  [ndo_select_queue has 3 params with no fallback])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ndo_select_queue has a second net_device parameter])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

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
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SELECT_QUEUE_NET_DEVICE, 1,
			  [ndo_select_queue has a second net_device parameter])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if include/linux/cleanup.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/cleanup.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_CLEANUP_H, 1,
			[include/linux/cleanup.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if include/linux/container_of.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/container_of.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_CONTAINER_OF_H, 1,
			[include/linux/container_of.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if include/linux/panic.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/panic.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PANIC_H, 1,
			[include/linux/panic.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if include/linux/bits.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/bits.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BITS_H, 1,
			[include/linux/bits.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if include/net/devlink.h devlink_alloc_ns defined])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/devlink.h>
	],[
		devlink_alloc_ns(NULL, 0, NULL, NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_ALLOC_NS, 1,
			  [include/net/devlink.h devlink_alloc_ns defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct flow_dissector_key_vlan has vlan_eth_type])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_dissector.h>
	],[
		struct flow_dissector_key_vlan vlan;

		vlan.vlan_eth_type = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_DISSECTOR_KEY_VLAN_ETH_TYPE, 1,
			  [struct flow_dissector_key_vlan has vlan_eth_type])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if FLOW_ACTION_CONTINUE exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		enum flow_action_id action = FLOW_ACTION_CONTINUE;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_ACTION_CONTINUE, 1,
			  [FLOW_ACTION_CONTINUE exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if FLOW_ACTION_JUMP and PIPE exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		enum flow_action_id action = FLOW_ACTION_JUMP;
		enum flow_action_id action2 = FLOW_ACTION_PIPE;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_ACTION_JUMP_AND_PIPE, 1,
			  [FLOW_ACTION_JUMP and PIPE exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if FLOW_ACTION_PRIORITY exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		enum flow_action_id action = FLOW_ACTION_PRIORITY;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_ACTION_PRIORITY, 1,
			  [FLOW_ACTION_PRIORITY exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if FLOW_ACTION_VLAN_PUSH_ETH exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		enum flow_action_id action = FLOW_ACTION_VLAN_PUSH_ETH;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_ACTION_VLAN_PUSH_ETH, 1,
			  [FLOW_ACTION_VLAN_PUSH_ETH exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if HAVE_FLOW_OFFLOAD_ACTION exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		struct flow_offload_action act = {};
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_OFFLOAD_ACTION, 1,
			  [HAVE_FLOW_OFFLOAD_ACTION exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if flow_offload_has_one_action exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		struct flow_action action;

		flow_offload_has_one_action(&action);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_OFFLOAD_HAS_ONE_ACTION, 1,
			  [flow_offload_has_one_action exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pkt_cls.h has tc_setup_flow_action])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/pkt_cls.h>
	],[
		tc_setup_flow_action(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TC_SETUP_FLOW_ACTION_FUNC, 1,
			  [tc_setup_flow_action is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pkt_cls.h has tc_setup_offload_action])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/pkt_cls.h>
	],[
		tc_setup_offload_action(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TC_SETUP_OFFLOAD_ACTION_FUNC, 1,
			  [tc_setup_offload_action is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pkt_cls.h has tc_setup_offload_action get 3 param])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/pkt_cls.h>
	],[
		tc_setup_offload_action(NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TC_SETUP_OFFLOAD_ACTION_FUNC_HAS_3_PARAM, 1,
			  [tc_setup_offload_action is defined and get 3 param])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pkt_cls.h has tc_setup_flow_action with rtnl_held])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/pkt_cls.h>
	],[
		tc_setup_flow_action(NULL, NULL, false);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TC_SETUP_FLOW_ACTION_WITH_RTNL_HELD, 1,
			  [tc_setup_flow_action has rtnl_held])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pkt_cls.h has __tc_indr_block_cb_register])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/pkt_cls.h>
	],[
		__tc_indr_block_cb_register(NULL, NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE___TC_INDR_BLOCK_CB_REGISTER, 1,
			  [__tc_indr_block_cb_register is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pkt_cls.h has TC_CLSMATCHALL_STATS])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/pkt_cls.h>
	],[
		enum tc_matchall_command x = TC_CLSMATCHALL_STATS;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TC_CLSMATCHALL_STATS, 1,
			  [TC_CLSMATCHALL_STATS is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if have __flow_indr_block_cb_register])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		__flow_indr_block_cb_register(NULL, NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE___FLOW_INDR_BLOCK_CB_REGISTER, 1,
			  [__flow_indr_block_cb_register is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if have flow_cls_offload_flow_rule])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		flow_cls_offload_flow_rule(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_CLS_OFFLOAD_FLOW_RULE, 1,
			  [flow_cls_offload_flow_rule is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if have flow_block_cb_setup_simple])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		flow_block_cb_setup_simple(NULL, NULL, NULL, NULL, NULL, false);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_BLOCK_CB_SETUP_SIMPLE, 1,
			  [flow_block_cb_setup_simple is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if have flow_block_cb_alloc])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		flow_block_cb_alloc(NULL, NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_BLOCK_CB_ALLOC, 1,
			  [flow_block_cb_alloc is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if have flow_setup_cb_t])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		flow_setup_cb_t *cb = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_SETUP_CB_T, 1,
			  [flow_setup_cb_t is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/ipv6_stubs.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/ipv6_stubs.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IPV6_STUBS_H, 1,
			  [net/ipv6_stubs.h exists])
	],[
		AC_MSG_RESULT(no)
	])

       AC_MSG_CHECKING([if net/rps.h exists])
       MLNX_BG_LB_LINUX_TRY_COMPILE([
              #include <net/rps.h>
       ],[
              return 0;
       ],[
              AC_MSG_RESULT(yes)
              MLNX_AC_DEFINE(HAVE_RPS_H, 1,
                       [net/rps.h exists])
       ],[
              AC_MSG_RESULT(no)
       ])

	AC_MSG_CHECKING([if struct net_device_ops has ndo_eth_ioctl])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct net_device_ops netdev_ops = {
			.ndo_eth_ioctl = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_ETH_IOCTL, 1,
			  [net_device_ops has ndo_eth_ioctl is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops has ndo_get_port_parent_id])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int get_port_parent_id(struct net_device *dev,
				       struct netdev_phys_item_id *ppid)
		{
			return 0;
		}
	],[
		struct net_device_ops netdev_ops;

		netdev_ops.ndo_get_port_parent_id = get_port_parent_id;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_GET_PORT_PARENT_ID, 1,
			  [HAVE_NDO_GET_PORT_PARENT_ID is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has struct netdev_nested_priv])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct netdev_nested_priv x;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_NESTED_PRIV_STRUCT, 1,
			  [netdevice.h has struct netdev_nested_priv])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if dev_get_port_parent_id exists])
        MLNX_BG_LB_LINUX_TRY_COMPILE([
        #include <linux/netdevice.h>
        ],[
                dev_get_port_parent_id(NULL, NULL, 0);
                return 0;
        ],[
                AC_MSG_RESULT(yes)
                MLNX_AC_DEFINE(HAVE_DEV_GET_PORT_PARENT_ID, 1,
                        [function dev_get_port_parent_id exists])
        ],[
                AC_MSG_RESULT(no)
        ])

	AC_MSG_CHECKING([if dev_addr_mod exists])
        MLNX_BG_LB_LINUX_TRY_COMPILE([
        #include <linux/netdevice.h>
        ],[
                dev_addr_mod(NULL, 0, NULL, 0);
                return 0;
        ],[
                AC_MSG_RESULT(yes)
                MLNX_AC_DEFINE(HAVE_DEV_ADDR_MOD, 1,
                        [function dev_addr_mod exists])
        ],[
                AC_MSG_RESULT(no)
        ])

	AC_MSG_CHECKING([if netdev_get_xmit_slave exists])
        MLNX_BG_LB_LINUX_TRY_COMPILE([
        #include <linux/netdevice.h>
        ],[
                netdev_get_xmit_slave(NULL, NULL, 0);
                return 0;
        ],[
                AC_MSG_RESULT(yes)
                MLNX_AC_DEFINE(HAVE_NETDEV_GET_XMIT_SLAVE, 1,
                        [function netdev_get_xmit_slave exists])
        ],[
                AC_MSG_RESULT(no)
        ])

        AC_MSG_CHECKING([if net/lag.h exists])
        MLNX_BG_LB_LINUX_TRY_COMPILE([
                #include <net/lag.h>
        ],[
                return 0;
        ],[
                AC_MSG_RESULT(yes)
                MLNX_AC_DEFINE(HAVE_NET_LAG_H, 1,
                          [net/lag.h exists])
        ],[
                AC_MSG_RESULT(no)
        ])

	AC_MSG_CHECKING([if net/lag.h net_lag_port_dev_txable exists])
        MLNX_BG_LB_LINUX_TRY_COMPILE([
                #include <net/lag.h>
        ],[
		net_lag_port_dev_txable(NULL);

                return 0;
        ],[
                AC_MSG_RESULT(yes)
                MLNX_AC_DEFINE(HAVE_NET_LAG_PORT_DEV_TXABLE, 1,
                          [net/lag.h exists])
        ],[
                AC_MSG_RESULT(no)
        ])

	AC_MSG_CHECKING([if ndo_get_ringparam get 4 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
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
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_RINGPARAM_GET_4_PARAMS, 1,
			  [ndo_get_ringparam get 4 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ndo_get_coalesce get 4 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>

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
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_GET_COALESCE_GET_4_PARAMS, 1,
			  [ndo_get_coalesce get 4 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops has get_pause_stats])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.get_pause_stats = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_PAUSE_STATS, 1,
			  [get_pause_stats is defined])
	],[
		AC_MSG_RESULT(no)
	])

        AC_MSG_CHECKING([if struct ethtool_ops has get_link_ext_state])
        MLNX_BG_LB_LINUX_TRY_COMPILE([
                #include <linux/ethtool.h>
        ],[
                const struct ethtool_ops en_ethtool_ops = {
                        .get_link_ext_state = NULL,
                };

                return 0;
        ],[
                AC_MSG_RESULT(yes)
                MLNX_AC_DEFINE(HAVE_GET_LINK_EXT_STATE, 1,
                          [.get_link_ext_state is defined])
        ],[
                AC_MSG_RESULT(no)
        ])

	AC_MSG_CHECKING([if net/tls.h has tls_offload_rx_resync_async_request_start])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/tls.h>
	],[
		tls_offload_rx_resync_async_request_start(NULL, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TLS_OFFLOAD_RX_RESYNC_ASYNC_REQUEST_START, 1,
			  [net/tls.h has tls_offload_rx_resync_async_request_start])
	],[
		AC_MSG_RESULT(no)
	])

       AC_MSG_CHECKING([if ethtool supports 50G-pre-lane link modes])
       MLNX_BG_LB_LINUX_TRY_COMPILE([
              #include <uapi/linux/ethtool.h>
       ],[
              const enum ethtool_link_mode_bit_indices speeds[] = {
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
       ],[
              AC_MSG_RESULT(yes)
              MLNX_AC_DEFINE(HAVE_ETHTOOL_50G_PER_LANE_LINK_MODES, 1,
                        [ethtool supprts 50G-pre-lane link modes])
       ],[
              AC_MSG_RESULT(no)
       ])

	AC_MSG_CHECKING([if struct ethtool_ops has get/set_rxfh_context])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.get_rxfh_context = NULL,
			.set_rxfh_context = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GET_RXFH_CONTEXT, 1,
			  [get/set_rxfh_context is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if kernel supports v6.11 'core tracks custom RSS contexts set'])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
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
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_CORE_TRACKS_CUSTOM_RSS_CONTEXTS, 1,
			  [kernel supports v6.11 'core tracks custom RSS contexts set'])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct ethtool_ops has get/set_settings])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		const struct ethtool_ops en_ethtool_ops = {
			.get_settings = NULL,
			.set_settings = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ETHTOOL_GET_SET_SETTINGS, 1,
			  [get/set_settings is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/ethtool_netlink.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool_netlink.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ETHTOOL_NETLINK_H, 1,
			  [linux/ethtool_netlink.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci.h has pci_msix_can_alloc_dyn])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		bool ret;

		ret = pci_msix_can_alloc_dyn(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_MSIX_CAN_ALLOC_DYN, 1,
			  [pci.h has pci_msix_can_alloc_dyn])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if cpu_rmap.h has irq_cpu_rmap_remove])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/cpu_rmap.h>
	],[
		int ret;

		ret = irq_cpu_rmap_remove(NULL,0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IRQ_CPU_RMAP_REMOVE, 1,
			  [cpu_rmap.h has irq_cpu_rmap_remove])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if irq.h has irq_get_effective_affinity_mask])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/irq.h>
		#include <linux/cpumask.h>
	],[
		irq_get_effective_affinity_mask(0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IRQ_GET_EFFECTIVE_AFFINITY_MASK, 1,
			  [irq_get_effective_affinity_mask is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pkt_cls.h enum enum tc_fl_command has TC_CLSFLOWER_STATS])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/pkt_cls.h>
	],[
		enum tc_fl_command x = TC_CLSFLOWER_STATS;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TC_CLSFLOWER_STATS_FIX, 1,
			  [pkt_cls.h enum enum tc_fl_command has TC_CLSFLOWER_STATS])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct tc_cls_flower_offload has stats field])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/pkt_cls.h>
	],[
		struct tc_cls_flower_offload *f;
		struct flow_stats stats;

		f->stats = stats;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TC_CLS_FLOWER_OFFLOAD_HAS_STATS_FIELD_FIX, 1,
			  [struct tc_cls_flower_offload has stats field])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/inetdevice.h has for_ifa define])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <linux/inetdevice.h>
        ],[
		struct in_device *in_dev;

		for_ifa(in_dev) {
		}

		endfor_ifa(in_dev);
        ],[
                AC_MSG_RESULT(yes)
                MLNX_AC_DEFINE(HAVE_FOR_IFA, 1,
                          [for_ifa defined])
        ],[
                AC_MSG_RESULT(no)
        ])

	AC_MSG_CHECKING([if netdevice.h has netdev_port_same_parent_id])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netdev_port_same_parent_id(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_PORT_SAME_PARENT_ID, 1,
			  [netdev_port_same_parent_id is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdev_features.h has NETIF_F_HW_TLS_RX])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdev_features.h>
	],[
		netdev_features_t tls_rx = NETIF_F_HW_TLS_RX;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_F_HW_TLS_RX, 1,
			[NETIF_F_HW_TLS_RX is defined in netdev_features.h])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if tls_offload_context_tx has destruct_work as member])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/tls.h>
	],[
		struct tls_offload_context_tx tls_ctx_tx;
		memset(&tls_ctx_tx.destruct_work, 0, sizeof(struct work_struct));

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TLS_OFFLOAD_DESTRUCT_WORK, 1,
			  [tls_offload_context_tx has destruct_work as member])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ndo_add_vxlan_port have udp_tunnel_info])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		#if IS_ENABLED(CONFIG_VXLAN)
		void add_vxlan_port(struct net_device *dev, struct udp_tunnel_info *ti)
		{
			return;
		}
		#endif

	],[
		struct net_device_ops netdev_ops;
		netdev_ops.ndo_udp_tunnel_add = add_vxlan_port;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_UDP_TUNNEL_ADD, 1,
			[ndo_add_vxlan_port is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ipv6_stub has ipv6_dst_lookup_flow])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/addrconf.h>
		#include <net/ipv6_stubs.h>
	],[
		int x = ipv6_stub->ipv6_dst_lookup_flow(NULL, NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IPV6_DST_LOOKUP_FLOW, 1,
			  [if ipv6_stub has ipv6_dst_lookup_flow])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ipv6_stub has ipv6_dst_lookup_flow in addrconf.h])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/addrconf.h>
	],[
		int x = ipv6_stub->ipv6_dst_lookup_flow(NULL, NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IPV6_DST_LOOKUP_FLOW_ADDR_CONF, 1,
			  [if ipv6_stub has ipv6_dst_lookup_flow in addrconf.h])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if nla_policy has validation_type])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/netlink.h>
	],[
		struct nla_policy x;
		x.validation_type = NLA_VALIDATE_MIN;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NLA_POLICY_HAS_VALIDATION_TYPE, 1,
			  [nla_policy has validation_type])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netlink.h has nla_strscpy])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/netlink.h>
	],[
		nla_strscpy(NULL, NULL ,0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NLA_STRSCPY, 1,
			  [nla_strscpy exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netlink.h has nla_nest_start_noflag])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/netlink.h>
	],[
		nla_nest_start_noflag(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NLA_NEST_START_NOFLAG, 1,
			  [nla_nest_start_noflag exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netlink.h has nlmsg_validate_deprecated ])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/netlink.h>
	],[
		nlmsg_validate_deprecated(NULL, 0, 0, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NLMSG_VALIDATE_DEPRECATED, 1,
			  [nlmsg_validate_deprecated exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netlink.h has nlmsg_parse_deprecated ])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/netlink.h>
	],[
		nlmsg_parse_deprecated(NULL, 0, NULL, 0, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NLMSG_PARSE_DEPRECATED, 1,
			  [nlmsg_parse_deprecated exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netlink.h has nla_parse_deprecated ])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/netlink.h>
	],[
		nla_parse_deprecated(NULL, 0, NULL, 0, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NLA_PARSE_DEPRECATED, 1,
			  [nla_parse_deprecated exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct genl_ops has member validate])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/genetlink.h>
	],[
		struct genl_ops x;

		x.validate = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GENL_OPS_VALIDATE, 1,
			  [struct genl_ops has member validate])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct genl_family has member resv_start_op])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/genetlink.h>
	],[
		struct genl_family x;

		x.resv_start_op = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GENL_FAMILY_RESV_START_OP, 1,
			  [struct genl_family has member resv_start_op])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct genl_family has member policy])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/genetlink.h>
	],[
		struct genl_family x;

		x.policy = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GENL_FAMILY_POLICY, 1,
			  [struct genl_family has member policy])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct netlink_callback has member extack])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netlink.h>
	],[
		struct netlink_callback x;

		x.extack = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETLINK_CALLBACK_EXTACK, 1,
			  [struct netlink_callback has member extack])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if sysfs.h has sysfs_emit])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sysfs.h>
	],[
		sysfs_emit(NULL, "");

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SYSFS_EMIT, 1,
			  [sysfs_emit is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ethtool.h has struct ethtool_pause_stats])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		struct ethtool_pause_stats x;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ETHTOOL_PAUSE_STATS, 1,
			  [ethtool_pause_stats is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ethtool.h has struct ethtool_rmon_hist_range])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		struct ethtool_rmon_hist_range x;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ETHTOOL_RMON_HIST_RANGE, 1,
			  [ethtool_rmon_hist_range is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ethtool.h has get_link_ext_stats])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		struct ethtool_ops x = {
			.get_link_ext_stats = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_LINK_EXT_STATS, 1,
			[get_link_ext_stats is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ethtool.h has ndo eth_phy_stats])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		struct ethtool_ops x = {
			.get_eth_phy_stats = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_ETH_PHY_STATS, 1,
			[eth_phy_stats is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ethtool.h has ndo get_fec_stats])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ethtool.h>
	],[
		struct ethtool_ops x = {
			.get_fec_stats = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_GET_FEC_STATS, 1,
			[get_fec_stats is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if skbuff.h has skb_set_redirected])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		struct sk_buff x;
		skb_set_redirected(&x, false);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SKB_SET_REDIRECTED, 1,
			  [skb_set_redirected is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if addrconf.h ipv6_dst_lookup takes net])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/addrconf.h>
	],[
		int x = ipv6_stub->ipv6_dst_lookup(NULL, NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IPV6_DST_LOOKUP_TAKES_NET, 1,
			  [ipv6_dst_lookup takes net])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if build_bug.h has static_assert])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/build_bug.h>
                #define A 5
                #define B 6
	],[
                static_assert(A < B);

                return 0;
        ],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_STATIC_ASSERT, 1,
			[build_bug.h has static_assert])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if register_fib_notifier has 4 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/fib_notifier.h>
	],[
		register_fib_notifier(NULL, NULL, NULL, NULL);
	],[
	AC_MSG_RESULT(yes)
	MLNX_AC_DEFINE(HAVE_REGISTER_FIB_NOTIFIER_HAS_4_PARAMS, 1,
		[register_fib_notifier has 4 params])
	],[
	AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if function fib_info_nh exists in file net/nexthop.h])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/nexthop.h>
	],[
		fib_info_nh(NULL, 0);
                return 0;
        ],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FIB_INFO_NH, 1,
			[function fib_info_nh exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if function fib6_info_nh_dev exists in file net/nexthop.h])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/nexthop.h>
	],[
		fib6_info_nh_dev(NULL);
                return 0;
        ],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FIB6_INFO_NH_DEV, 1,
			[function fib6_info_nh_dev exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/kobject.h kobj_type has default_groups member])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/kobject.h>
	],[
		struct kobj_type x = {
			.default_groups = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_KOBJ_TYPE_DEFAULT_GROUPS, 1,
			[linux/kobject.h kobj_type has default_groups member])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/lockdep.h has lockdep_unregister_key])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/lockdep.h>
	],[
		lockdep_unregister_key(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_LOCKDEP_UNREGISTER_KEY, 1,
			[linux/lockdep.h has lockdep_unregister_key])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/lockdep.h has lockdep_assert_held_exclusive])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/lockdep.h>
	],[
		lockdep_assert_held_exclusive(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_LOCKUP_ASSERT_HELD_EXCLUSIVE, 1,
			[linux/lockdep.h has lockdep_assert_held_exclusive])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/lockdep.h has lockdep_assert_held_write])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/lockdep.h>
	],[
		lockdep_assert_held_write(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_LOCKUP_ASSERT_HELD_WRITE, 1,
			[linux/lockdep.h has lockdep_assert_held_write])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if fib_nh has fib_nh_dev])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/ip_fib.h>
	],[
		struct fib_nh x = {
			.fib_nh_dev = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FIB_NH_DEV, 1,
			[fib_nh has fib_nh_dev])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct page has dma_addr])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mm_types.h>
	],[
		struct page x = {
			.dma_addr = 0
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PAGE_DMA_ADDR, 1,
			  [struct page has dma_addr])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct mm_struct has member atomic_pinned_vm])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mm_types.h>
	],[
		struct mm_struct x;
                atomic64_t y;
		x.pinned_vm = y;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ATOMIC_PINNED_VM, 1,
			  [atomic_pinned_vm is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct mm_struct has member pinned_vm])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mm_types.h>
	],[
		struct mm_struct x;
		x.pinned_vm = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PINNED_VM, 1,
			  [pinned_vm is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if route.h struct rtable has member rt_gw_family])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/route.h>
	],[
		struct rtable x = {
			.rt_gw_family = 0,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_RT_GW_FAMILY, 1,
			  [rt_gw_family is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if route.h struct rtable has member rt_uses_gateway])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/route.h>
	],[
		struct rtable x = {
			.rt_uses_gateway = 0,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_RT_USES_GATEWAY, 1,
			  [rt_uses_gateway is defined])
	],[
		AC_MSG_RESULT(no)
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

	AC_MSG_CHECKING([if pci.h has pci_pool_zalloc])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		pci_pool_zalloc(NULL, 0, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_POOL_ZALLOC, 1,
			  [pci_pool_zalloc is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops has *ndo_bridge_setlink])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
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
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_BRIDGE_SETLINK, 1,
			  [ndo_bridge_setlink is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops has *ndo_bridge_setlink])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		int bridge_setlink(struct net_device *dev, struct nlmsghdr *nlh,
				   u16 flags, struct netlink_ext_ack *extack)
		{
			return 0;
		}
	],[
		struct net_device_ops netdev_ops;
		netdev_ops.ndo_bridge_setlink = bridge_setlink;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_BRIDGE_SETLINK_EXTACK, 1,
			  [ndo_bridge_setlink is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct net_device_ops has *ndo_get_vf_guid])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
		#include <linux/if_link.h>

		int get_vf_guid(struct net_device *dev, int vf, struct ifla_vf_guid *node_guid,
                                                   struct ifla_vf_guid *port_guid)

		{
			return 0;
		}
	],[
		struct net_device_ops netdev_ops;
		netdev_ops.ndo_get_vf_guid = get_vf_guid;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_GET_VF_GUID, 1,
			  [ndo_get_vf_guid is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci.h has pci_irq_get_node])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		pci_irq_get_node(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_IRQ_GET_NODE, 1,
			  [pci_irq_get_node is defined])
	],[
		AC_MSG_RESULT(no)
	])

	LB_CHECK_SYMBOL_EXPORT([fib_lookup],
		[net/ipv4/fib_rules.c],
		[AC_DEFINE(HAVE_FIB_LOOKUP_EXPORTED, 1,
			[fib_lookup is exported by the kernel])],
	[])

	AC_MSG_CHECKING([if idr.h has ida_free])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/idr.h>
	],[
		ida_free(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IDA_FREE, 1,
			  [idr.h has ida_free])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if idr.h has ida_alloc_range])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/idr.h>
	],[
		ida_alloc_range(NULL, 0, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IDA_ALLOC_RANGE, 1,
			  [idr.h has ida_alloc_range])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if idr.h has ida_alloc])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/idr.h>
	],[
		ida_alloc(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IDA_ALLOC, 1,
			  [ida_alloc is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if idr.h has ida_alloc_max])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/idr.h>
	],[
		ida_alloc_max(NULL, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IDA_ALLOC_MAX, 1,
			  [ida_alloc_max is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if xarray is defined])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/xarray.h>
	],[
		struct xa_limit x;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XARRAY, 1,
			[xa_array is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if xa_for_each_range is defined])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/xarray.h>
	],[
		#ifdef xa_for_each_range
			return 0;
		#else
			#return 1;
		#endif
	],[
	AC_MSG_RESULT(yes)
	MLNX_AC_DEFINE(HAVE_XA_FOR_EACH_RANGE, 1,
		[xa_for_each_range is defined])
	],[
	AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if DEFINE_SEQ_ATTRIBUTE is defined])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/seq_file.h>
	],[
		#ifdef DEFINE_SEQ_ATTRIBUTE
			return 0;
		#else
			#return 1;
		#endif
	],[
	AC_MSG_RESULT(yes)
	MLNX_AC_DEFINE(HAVE_DEFINE_SEQ_ATTRIBUTE, 1,
		[DEFINE_SEQ_ATTRIBUTE is defined])
	],[
	AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if fd_file is defined])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/file.h>
	],[
		struct fd file_des = EMPTY_FD;
		struct file *f = fd_file(file_des);

		return 0;
	],[
	AC_MSG_RESULT(yes)
	MLNX_AC_DEFINE(HAVE_FD_FILE, 1,
		[fd_file is defined])
	],[
	AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi_cmd_to_rq is defind])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_cmnd.h>
	],[
		scsi_cmd_to_rq(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SCSI_CMD_TO_RQ, 1,
			  [scsi_cmd_to_rq is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi_done is defind])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_cmnd.h>
	],[
		scsi_done(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SCSI_DONE, 1,
			  [scsi_done is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi_get_sector is defind])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_cmnd.h>
	],[
		scsi_get_sector(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SCSI_GET_SECTOR, 1,
			  [scsi_get_sector is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if string.h has strscpy_pad])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/string.h>
	],[
		strscpy_pad(NULL, NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_STRSCPY_PAD, 1,
			  [strscpy_pad is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net_namespace get const struct device])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
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
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NET_NAMESPACE_GET_CONST_DEVICE, 1,
			  [net_namespace get const struct device])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if dev_uevent get const struct device])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/device.h>
		static int foo(const struct device *dev, struct kobj_uevent_env *env) {
			return 0;
		}

	],[
		struct class my_class = {
			.dev_uevent = foo,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_CLASS_DEV_UEVENT_CONST_DEV, 1,
			  [dev_uevent get const struct device])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if devnode get const struct device])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/device.h>
		static char * foo(const struct device *dev,  umode_t *mode) {
			return NULL;
		}

	],[
		struct class my_class = {
			.devnode = foo,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVNODE_GET_CONST_DEVICE, 1,
			  [devnode get const struct device])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if bus_type enty of struct device is const])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/device.h>
	],[
		struct device dev;
		const struct bus_type bt;

		dev.bus = &bt;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_CONST_BUS_TYPE_FOR_STRUCT_DEVICE, 1,
			  [bus_type enty of struct device is const])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if bus_find_device get const])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/device.h>
	],[
		const void *data;
 		bus_find_device(NULL, NULL, data, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BUS_FIND_DEVICE_GET_CONST, 1,
			  [bus_find_device get const])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netns_ipv4 tcp_death_row memebr is not pointer])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/netns/ipv4.h>

	],[
		struct inet_timewait_death_row row;

		struct netns_ipv4 x = {
			.tcp_death_row = row,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IPV4_NOT_POINTER_TCP_DEATH_ROW, 1,
			  [netns_ipv4 tcp_death_row memebr is not pointer])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h if struct rtnl_link_ops has netns_refund])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/rtnetlink.h>

	],[
		struct rtnl_link_ops x = {
			.netns_refund = 0,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_STRUCT_LINK_OPS_IPOIB_LINK_OPS_HAS_NETNS_REFUND, 1,
			  [struct rtnl_link_ops has netns_refund])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/eventfd.h has eventfd_signal with 1 param])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/eventfd.h>
	],[

		eventfd_signal(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_EVENTFD_SIGNAL_GET_1_PARAM, 1,
			  [linux/eventfd.h has eventfd_signal with 1 param])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/ipv6.h has struct hop_jumbo_hdr])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/ipv6.h>
	],[

		struct hop_jumbo_hdr jumbo;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_STRUCT_HOP_JUMBO_HDR, 1,
			  [net/ipv6.h has struct  hop_jumbo_hdr])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netdev_xmit_more])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netdev_xmit_more();

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_XMIT_MORE, 1,
			  [netdev_xmit_more is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if mm.h has FOLL_LONGTERM])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mm.h>
	],[
		int x = FOLL_LONGTERM;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FOLL_LONGTERM, 1,
			[FOLL_LONGTERM is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/dma-mapping.h has dma_pci_p2pdma_supported])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/dma-mapping.h>
	],[
		dma_pci_p2pdma_supported(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DMA_PCI_P2PDMA_SUPPORTED, 1,
			  [linux/dma-mapping.h has dma_pci_p2pdma_supported])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/proc_fs.h has pde_data])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/proc_fs.h>
	],[
		pde_data(NULL);
		return 0;

	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PDE_DATA, 1,
			  [linux/proc_fs.h has pde_data])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/proc_fs.h has struct proc_ops])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/proc_fs.h>
	],[
		struct proc_ops x = {
			.proc_open    = NULL,
		        .proc_read    = NULL,
		        .proc_lseek  = NULL,
		        .proc_release = NULL,
		};

		return 0;

	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PROC_OPS_STRUCT, 1,
			  [struct proc_ops is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blk_mark_disk_dead exist])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		blk_mark_disk_dead(NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MARK_DISK_DEAD, 1,
			[blk_mark_disk_dead exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if dma-mapping.h has dma_zalloc_coherent function])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/dma-mapping.h>
	],[
		dma_zalloc_coherent(NULL, 0, NULL, GFP_KERNEL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DMA_ZALLOC_COHERENT, 1,
			  [dma-mapping.h has dma_zalloc_coherent function])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/xdp.h has xdp_set_features_flag])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xdp.h>

	],[
		xdp_set_features_flag(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XDP_SET_FEATURES_FLAG, 1,
			  [xdp_set_features_flag defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/xdp_sock_drv.h has xsk_buff_alloc])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xdp_sock_drv.h>
	],[
		xsk_buff_alloc(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XSK_BUFF_ALLOC, 1,
			  [xsk_buff_alloc is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/xdp_sock_drv.h has xsk_buff_alloc_batch])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xdp_sock_drv.h>
	],[
		xsk_buff_alloc_batch(NULL, NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XSK_BUFF_ALLOC_BATCH, 1,
			  [xsk_buff_alloc_batch is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/xdp_sock_drv.h has xsk_buff_set_size])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xdp_sock_drv.h>
	],[
		xsk_buff_set_size(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XSK_BUFF_SET_SIZE, 1,
			  [xsk_buff_set_size is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/xdp_sock_drv.h has xsk_buff_xdp_get_frame_dma])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xdp_sock_drv.h>
	],[
		xsk_buff_xdp_get_frame_dma(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XSK_BUFF_GET_FRAME_DMA, 1,
			  [xsk_buff_xdp_get_frame_dma is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if kernel supports v6.10-rc1, skip calling no-op sync ops when possible])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/page_pool/types.h>
	],[
		struct page_pool pp = {
			.has_init_callback = 1,
			.dma_map = 1,
			.dma_sync = 1,
			.pages_state_hold_cnt = 1,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SKIP_CALLING_NOP_SYNC_OPS, 1,
			  [kernel supports v6.10-rc1, skip calling no-op sync ops when possible])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if kernel supports v6.10-rc1: convert __be16 tunnel flags to bitmaps])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/ip_tunnels.h>
	],[
		struct ip_tunnel_parm_kern itpk = {
			.link = 1,
			.i_flags = 1,
			.o_flags = 1,
		};

		IP_TUNNEL_DECLARE_FLAGS(present) = { };
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_CONVERT_BE16_TUNNEL_FLAGS_TO_BITMAPS, 1,
			  [kernel supports v6.10-rc1: convert __be16 tunnel flags to bitmaps])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/xdp_sock.h has struct xsk_tx_metadata_ops])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xdp_sock.h>
	],[

		const struct xsk_tx_metadata_ops mlx5e_xsk_tx_metadata_ops = {
			.tmo_fill_timestamp             = NULL,
			.tmo_request_checksum           = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XSK_TX_METADATA_OPS, 1,
			  [struct xsk_tx_metadata_ops is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/xdp_sock.h has xsk_umem_release_addr_rq])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xdp_sock.h>
	],[
		xsk_umem_release_addr_rq(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XSK_UMEM_RELEASE_ADDR_RQ, 1,
			  [xsk_umem_release_addr_rq is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/xdp_sock.h has xsk_umem_adjust_offset])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xdp_sock.h>
	],[
		xsk_umem_adjust_offset(NULL, 0, 0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XSK_UMEM_ADJUST_OFFSET, 1,
			  [xsk_umem_adjust_offset is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/xdp_soc_drv.h has xsk_umem_consume_tx get 2 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xdp_sock_drv.h>
	],[
		xsk_umem_consume_tx(NULL,NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XSK_UMEM_CONSUME_TX_GET_2_PARAMS_IN_SOCK_DRV, 1,
			  [net/xdp_soc_drv.h has xsk_umem_consume_tx get 2 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/xdp_sock.h has xsk_umem_consume_tx get 2 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xdp_sock.h>
	],[
		xsk_umem_consume_tx(NULL,NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XSK_UMEM_CONSUME_TX_GET_2_PARAMS_IN_SOCK, 1,
			[net/xdp_sock.h has xsk_umem_consume_tx get 2 params])
	],[
		AC_MSG_RESULT(no)
	])

		 AC_MSG_CHECKING([if xdp_sock.h struct xdp_umem has member chunk_size])
		 MLNX_BG_LB_LINUX_TRY_COMPILE([
        		 #include <net/xdp_sock.h>
	 ],[
       		  struct xdp_umem xdp = {
                 .chunk_size = 0,
        		 };

         		return 0;
	 ],[
        	AC_MSG_RESULT(yes)
        	MLNX_AC_DEFINE(HAVE_XDP_UMEM_CHUNK_SIZE, 1,
                 		  [chunk_size is defined])
		 ],[
       		 AC_MSG_RESULT(no)
	 ])

		 AC_MSG_CHECKING([if xdp_sock.h struct xdp_umem has member flags])
		 MLNX_BG_LB_LINUX_TRY_COMPILE([
        		 #include <net/xdp_sock.h>
	 ],[
       		  struct xdp_umem xdp = {
                 .flags = 0,
        		 };

         		return 0;
	 ],[
        	AC_MSG_RESULT(yes)
        	MLNX_AC_DEFINE(HAVE_XDP_UMEM_FLAGS, 1,
                 		  [flags is defined])
		 ],[
       		 AC_MSG_RESULT(no)
	 ])

	AC_MSG_CHECKING([if filter.h has xdp_do_flush_map])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/filter.h>
	],[
		xdp_do_flush_map();

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XDP_DO_FLUSH_MAP, 1,
			  [filter.h has xdp_do_flush_map])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if filter.h has bpf_warn_invalid_xdp_action get 3 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/filter.h>
	],[
		bpf_warn_invalid_xdp_action(NULL, NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BPF_WARN_IVALID_XDP_ACTION_GET_3_PARAMS, 1,
			  [filter.h has bpf_warn_invalid_xdp_action get 3 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi.h has QUEUE_FULL])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi.h>
	],[
		int x = QUEUE_FULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SCSI_QUEUE_FULL, 1,
			  [QUEUE_FULL is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi_device.h has scsi_block_targets])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_device.h>
	],[
		scsi_block_targets(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SCSI_BLOCK_TARGETS, 1,
			[scsi_block_targets is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if iscsi_target_core.h has struct iscsit_conn])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <target/iscsi/iscsi_target_core.h>
	],[
		struct iscsit_conn c;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ISCSIT_CONN, 1,
			  [iscsi_target_core.h has struct iscsit_conn])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if iscsi_target_core.h struct iscsit_conn has member login_sockaddr])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <target/iscsi/iscsi_target_core.h>
	],[
		struct sockaddr_storage s;
		struct iscsit_conn c = {
			.login_sockaddr = s,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ISCSIT_CONN_LOGIN_SOCKADDR, 1,
			  [iscsit_conn has member login_sockaddr])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if iscsi_target_core.h struct iscsit_conn has member local_sockaddr])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <target/iscsi/iscsi_target_core.h>
	],[
		struct sockaddr_storage s;
		struct iscsit_conn c = {
			.local_sockaddr = s,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ISCSIT_CONN_LOCAL_SOCKADDR, 1,
			  [iscsit_conn has members local_sockaddr])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if iscsi_target_core.h struct iscsi_conn has member login_sockaddr])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <target/iscsi/iscsi_target_core.h>
	],[
		struct sockaddr_storage s;
		struct iscsi_conn c = {
			.login_sockaddr = s,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ISCSI_CONN_LOGIN_SOCKADDR, 1,
			  [iscsi_conn has member login_sockaddr])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if iscsi_target_core.h struct iscsi_conn has member local_sockaddr])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <target/iscsi/iscsi_target_core.h>
	],[
		struct sockaddr_storage s;
		struct iscsi_conn c = {
			.local_sockaddr = s,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ISCSI_CONN_LOCAL_SOCKADDR, 1,
			  [iscsi_conn has members local_sockaddr])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if iscsi_target_core.h has struct iscsit_cmd])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <target/iscsi/iscsi_target_core.h>
	],[
		struct iscsit_cmd c;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ISCSIT_CMD, 1,
			  [iscsi_target_core.h has struct iscsit_cmd])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if target/target_core_fabric.h has target_stop_session])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <target/target_core_base.h>
		#include <target/target_core_fabric.h>
	],[
		target_stop_session(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TARGET_STOP_SESSION, 1,
			  [target_stop_session is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if target/target_core_fabric.h has target_stop_cmd_counter])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <target/target_core_fabric.h>
	],[
		target_stop_cmd_counter(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TARGET_STOP_CMD_COUNTER, 1,
			  [target_stop_cmd_counter is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi_host.h struct scsi_host_template has member shost_groups])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_host.h>
	],[
		struct scsi_host_template sh = {
			.shost_groups = NULL,
		};
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SCSI_HOST_TEMPLATE_SHOST_GROUPS, 1,
			[scsi_host_template has members shost_groups])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi_host.h struct scsi_host_template has member init_cmd_priv])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_host.h>
	],[
		struct scsi_host_template sh = {
			.init_cmd_priv = NULL,
		};
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SCSI_HOST_TEMPLATE_INIT_CMD_PRIV, 1,
			[scsi_host_template has member init_cmd_priv])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi_host.h struct Scsi_Host has member max_segment_size])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_host.h>
	],[
		struct Scsi_Host sh = {
			.max_segment_size = 0,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SCSI_HOST_MAX_SEGMENT_SIZE, 1,
				[Scsi_Host has members max_segment_size])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi_host.h struct Scsi_Host has member virt_boundary_mask])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_host.h>
	],[
		struct Scsi_Host sh = {
			.virt_boundary_mask = 0,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SCSI_HOST_VIRT_BOUNDARY_MASK, 1,
				[Scsi_Host has members virt_boundary_mask])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi_host.h scsi_host_busy_iter fn has 2 args])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_host.h>

		bool fn(struct scsi_cmnd *scmnd, void *ctx)
		{
			return false;
		}
	],[
		scsi_host_busy_iter(NULL, fn, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SCSI_HOST_BUSY_ITER_FN_2_ARGS, 1,
				[scsi_host.h scsi_host_busy_iter fn has 2 args])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi_host.h has enum scsi_timeout_action])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_host.h>
	],[
		enum scsi_timeout_action a = SCSI_EH_DONE;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SCSI_TIMEOUT_ACTION, 1,
				[scsi_host.h has enum scsi_timeout_action])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi_host_alloc get const struct scsi_host_template])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_host.h>
	],[
		const struct scsi_host_template t = {};

		scsi_host_alloc(&t, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SCSI_HOST_ALLOC_GET_CONST_SHT, 1,
				[scsi_host_alloc get const struct scsi_host_template])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if target_core_base.h struct se_cmd has member sense_info])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <target/target_core_base.h>

	],[
		struct se_cmd se = {
			.sense_info = 0,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SE_CMD_HAS_SENSE_INFO, 1,
			[struct se_cmd has member sense_info])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi_device.h struct scsi_device has member budget_map])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_device.h>
	],[
		struct scsi_device sdev;
		sbitmap_init_node(&sdev.budget_map, 0, 0, 0, 0, false, false);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SCSI_DEVICE_BUDGET_MAP, 1,
			  [scsi_device.h struct scsi_device has member budget_map])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blk_types.h has enum req_opf])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk_types.h>
	],[
		enum req_opf xx = REQ_OP_DRV_OUT;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_TYPES_REQ_OPF, 1,
			  [enum req_opf is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if __cgroup_bpf_run_filter_sysctl have 7 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/bpf-cgroup.h>
	],[
		return __cgroup_bpf_run_filter_sysctl(NULL, NULL, 0, NULL, NULL, NULL, 0);
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_CGROUP_BPF_RUN_FILTER_SYSCTL_7_PARAMETERS, 1,
			[__cgroup_bpf_run_filter_sysctl have 7 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/pci-p2pdma.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci-p2pdma.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_P2PDMA_H, 1,
			  [linux/pci-p2pdma.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if trace/events/rdma_core.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <trace/events/rdma_core.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TRACE_EVENTS_RDMA_CORE_HEADER, 1,
			  [trace/events/rdma_core.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if __assign_str has one param])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
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
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ASSIGN_STR_1_PARAM, 1,
			  [__assign_str has one param])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci-p2pdma.h has pci_p2pdma_unmap_sg])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci-p2pdma.h>
	],[
		pci_p2pdma_unmap_sg(NULL, NULL, 0, 0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_P2PDMA_UNMAP_SG, 1,
			  [pci_p2pdma_unmap_sg defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct bpf_prog_aux has xdp_has_frags as member])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/bpf.h>
	],[
		struct bpf_prog_aux x = {
			.xdp_has_frags = true
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XDP_HAS_FRAGS, 1,
			  [struct bpf_prog_aux has xdp_has_frags as member])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/xdp.h has xdp_update_skb_shared_info])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xdp.h>
	],[
		xdp_update_skb_shared_info(NULL, 0, 0, 0, false);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XDP_UPDATE_SKB_SHARED_INFO, 1,
			  [xdp_update_skb_shared_info is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if xdp_metadata_ops has xmo_rx_vlan_tag])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xdp.h>
	],[
		const struct xdp_metadata_ops mlx5e_xdp_metadata_ops = {
			.xmo_rx_timestamp           = NULL,
			.xmo_rx_hash                = NULL,
			.xmo_rx_vlan_tag            = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XDP_METADATA_OPS_HAS_VLAN_TAG, 1,
			  [xdp_metadata_ops has xmo_rx_vlan_tag])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/xdp.h has xdp_get_shared_info_from_buff])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xdp.h>
	],[
		xdp_get_shared_info_from_buff(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XDP_GET_SHARED_INFO_FROM_BUFF, 1,
			  [xdp_update_skb_shared_info is defined])
	],[
		AC_MSG_RESULT(no)
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

	AC_MSG_CHECKING([if bpf_prog_add\bfs_prog_inc functions return struct])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/bpf.h>
	],[
		struct bpf_prog *prog;

		prog = bpf_prog_add(prog, 0);
		prog = bpf_prog_inc(prog);
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BPF_PROG_ADD_RET_STRUCT, 1,
			  [bpf_prog_add\bfs_prog_inc functions return struct])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct tc_cls_flower_offload has common])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/pkt_cls.h>
	],[
		struct tc_cls_flower_offload x = {
			.common = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TC_CLS_FLOWER_OFFLOAD_COMMON_FIX, 1,
			  [struct tc_cls_flower_offload has common])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct flow_cls_offload exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		struct flow_cls_offload x = {
			.classid = 3,
		};
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_CLS_OFFLOAD, 1,
			  [struct flow_cls_offload exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct flow_action_entry has ct_metadata.orig_dir])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		struct flow_action_entry x = {
			.ct_metadata.orig_dir = true,
		};
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_ACTION_CT_METADATA_ORIG_DIR, 1,
			  [struct flow_action_entry has ct_metadata.orig_dir])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct flow_action_entry has ptype])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		struct flow_action_entry x = {
			.ptype = 1,
		};
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_ACTION_PTYPE, 1,
			  [struct flow_action_entry has ptype])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct flow_action_entry has mpls])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		struct flow_action_entry x = {
			.mpls_push.label = 1,
		};
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_ACTION_MPLS, 1,
			  [struct flow_action_entry has mpls])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct flow_action_entry has police.index])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		struct flow_action_entry x = {
			.police.index = 1,
		};
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_ACTION_POLICE_INDEX, 1,
			  [struct flow_action_entry has police.index])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct flow_action_entry has police.exceed])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		struct flow_action_entry x = {
			.police.exceed.act_id = 1,
		};
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_ACTION_POLICE_EXCEED, 1,
			  [struct flow_action_entry has police.exceed])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct flow_action_entry has hw_index])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		struct flow_action_entry x = {
			.hw_index = 1,
		};
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_ACTION_HW_INDEX, 1,
			  [struct flow_action_entry has hw_index])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct flow_action_entry has police.rate_pkt_ps])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		struct flow_action_entry x = {
			.police.rate_pkt_ps = 1,
		};
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_ACTION_POLICE_RATE_PKT_PS, 1,
			  [struct flow_action_entry has police.rate_pkt_ps])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if flow_rule_match_meta exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		flow_rule_match_meta(NULL, NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_RULE_MATCH_META, 1,
			  [flow_rule_match_meta exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if flow_action_hw_stats_check exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		flow_action_hw_stats_check(NULL, NULL, 0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_ACTION_HW_STATS_CHECK, 1,
			  [flow_action_hw_stats_check exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if FLOW_ACTION_POLICE exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		enum flow_action_id action = FLOW_ACTION_POLICE;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_ACTION_POLICE, 1,
			  [FLOW_ACTION_POLICE exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if FLOW_ACTION_CT exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		enum flow_action_id action = FLOW_ACTION_CT;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_ACTION_CT, 1,
			  [FLOW_ACTION_CT exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if FLOW_ACTION_REDIRECT_INGRESS exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		enum flow_action_id action = FLOW_ACTION_REDIRECT_INGRESS;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_ACTION_REDIRECT_INGRESS, 1,
			  [FLOW_ACTION_REDIRECT_INGRESS exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if enum flow_block_binder_type exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		enum flow_block_binder_type binder_type;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ENUM_FLOW_BLOCK_BINDER_TYPE, 1,
			  [enum flow_block_binder_type exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if flow_indr_block_bind_cb_t has 7 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
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
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_INDR_BLOCK_BIND_CB_T_7_PARAMS, 1,
			  [flow_indr_block_bind_cb_t has 7 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if flow_indr_block_bind_cb_t has 4 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
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
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_INDR_BLOCK_BIND_CB_T_4_PARAMS, 1,
			  [flow_indr_block_bind_cb_t has 4 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if flow_indr_dev_unregister receive flow_setup_cb_t parameter])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
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
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_INDR_DEV_UNREGISTER_FLOW_SETUP_CB_T, 1,
			  [flow_indr_dev_unregister receive flow_setup_cb_t parameter])
	],[
		AC_MSG_RESULT(no)
	])


	AC_MSG_CHECKING([if flow_indr_dev_register exist])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
		#include <net/flow_offload.h>
	],[
		flow_indr_dev_register(NULL, NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_INDR_DEV_REGISTER, 1,
			  [flow_indr_dev_register exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if flow_stats_update has 5 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		flow_stats_update(NULL, 0, 0, 0, 0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_STATS_UPDATE_5_PARAMS, 1,
			  [flow_stats_update has 5 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if flow_stats_update has 6 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		flow_stats_update(NULL, 0, 0, 0, 0, 0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_STATS_UPDATE_6_PARAMS, 1,
			  [flow_stats_update has 6 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if GRO_LEGACY_MAX_SIZE defined])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		unsigned int x = GRO_LEGACY_MAX_SIZE;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GRO_LEGACY_MAX_SIZE, 1,
			  [GRO_LEGACY_MAX_SIZE defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if GRO_MAX_SIZE defined])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		unsigned long x = GRO_MAX_SIZE;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GRO_MAX_SIZE, 1,
			  [GRO_MAX_SIZE defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct mlx5e_netdev_ops has ndo_tx_timeout get 2 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>

		void mlx5e_tx_timeout(struct net_device *dev, unsigned int txqueue)
		{
			return;
		}
	],[
		struct net_device_ops mlx5e_netdev_ops = {
			.ndo_tx_timeout = mlx5e_tx_timeout,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NDO_TX_TIMEOUT_GET_2_PARAMS, 1,
			  [ndo_tx_timeout get 2 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/tc_act/tc_mpls.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/tc_act/tc_mpls.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NET_TC_ACT_TC_MPLS_H, 1,
			  [net/tc_act/tc_mpls.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/tc_act/tc_pedit.h struct tcf_pedit has member tcfp_keys_ex])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/tc_act/tc_pedit.h>
	],[
		struct tcf_pedit x = {
			.tcfp_keys_ex = NULL,
		};
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TCF_PEDIT_TCFP_KEYS_EX_FIX, 1,
			  [struct tcf_pedit has member tcfp_keys_ex])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/tc_act/tc_pedit.h struct tcf_pedit_parms has member tcfp_keys_ex])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/tc_act/tc_pedit.h>
	],[
		struct tcf_pedit_parms x = {
			.tcfp_keys_ex = NULL,
		};
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TCF_PEDIT_PARMS_TCFP_KEYS_EX, 1,
			  [struct tcf_pedit_parms has member tcfp_keys_ex])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if libiscsi.h has iscsi_eh_cmd_timed_out])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
		#include <scsi/libiscsi.h>
	],[
		iscsi_eh_cmd_timed_out(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ISCSI_EH_CMD_TIMED_OUT, 1,
			[iscsi_eh_cmd_timed_out is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if libiscsi.h has iscsi_conn_unbind])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/libiscsi.h>
	],[
		iscsi_conn_unbind(NULL, false);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ISCSI_CONN_UNBIND, 1,
			[iscsi_conn_unbind is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if libiscsi.h iscsi_host_remove has 2 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/libiscsi.h>
	],[
		iscsi_host_remove(NULL, false);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ISCSI_HOST_REMOVE_2_PARAMS, 1,
			[libiscsi.h iscsi_host_remove has 2 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if libiscsi.h has struct iscsi_cmd])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/libiscsi.h>
	],[
		struct iscsi_cmd c;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ISCSI_CMD, 1,
			[libiscsi.h has struct iscsi_cmd])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi_transport_iscsi.h has iscsi_put_endpoint])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_transport_iscsi.h>
	],[
		iscsi_put_endpoint(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ISCSI_PUT_ENDPOINT, 1,
			[iscsi_put_endpoint is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/sed-opal.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sed-opal.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_LINUX_SED_OPAL_H, 1,
			[linux/sed-opal.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if bio.h bio_init has 3 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/bio.h>
	],[
		bio_init(NULL, NULL, false);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BIO_INIT_3_PARAMS, 1,
			  [bio.h bio_init has 3 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if __auto_type exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/compiler.h>

		#define no_free_ptr(p) \
		        ({ __auto_type __ptr = (p); (p) = NULL; __ptr; })
	],[
		int * a;

		no_free_ptr(a);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_AUTO_TYPE, 1,
			[__auto_type exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if compiler.h has const __read_once_size])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/compiler.h>
	],[
		const unsigned long tmp;
		__read_once_size(&tmp, NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_CONST_READ_ONCE_SIZE, 1,
			[const __read_once_size exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/security.h has register_lsm_notifier])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/security.h>
	],[
		register_lsm_notifier(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_REGISTER_LSM_NOTIFIER, 1,
			  [linux/security.h has register_lsm_notifier])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/security.h has register_blocking_lsm_notifier])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/security.h>
	],[
		register_blocking_lsm_notifier(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_REGISTER_BLOCKING_LSM_NOTIFIER, 1,
			  [linux/security.h has register_blocking_lsm_notifier])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/dma-map-ops.h has DMA_F_PCI_P2PDMA_SUPPORTED])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/dma-map-ops.h>
	],[
		struct dma_map_ops * a;
		a->flags = DMA_F_PCI_P2PDMA_SUPPORTED;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DMA_F_PCI_P2PDMA_SUPPORTED, 1,
			  [linux/dma-map-ops.h has DMA_F_PCI_P2PDMA_SUPPORTED])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/atomic.h has __atomic_add_unless])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/highmem.h>
	],[
		atomic_t x;
		__atomic_add_unless(&x, 1, 1);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE___ATOMIC_ADD_UNLESS, 1,
			  [__atomic_add_unless is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/atomic.h has atomic_fetch_add_unless])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/highmem.h>
	],[
		atomic_t x;
		atomic_fetch_add_unless(&x, 1, 1);
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ATOMIC_FETCH_ADD_UNLESS, 1,
			  [atomic_fetch_add_unless is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/pkt_cls.h has tcf_exts_stats_update])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/pkt_cls.h>
	],[
		tcf_exts_stats_update(NULL, 0, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TCF_EXTS_STATS_UPDATE, 1,
			  [tcf_exts_stats_update is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct  tc_action_ops has id])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/act_api.h>
	],[
		struct tc_action_ops x = { .id = 0, };

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TC_ACTION_OPS_HAS_ID, 1,
			  [struct  tc_action_ops has id])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/iommu-dma.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/iommu.h>
		#include <linux/iommu-dma.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_LINUX_IOMMU_DMA_H, 1,
			[linux/iommu-dma.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if include/linux/unaligned.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/unaligned.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_LINUX_UNALIGNED_H, 1,
			[linux/unaligned.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/device/bus.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/device/bus.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_LINUX_DEVICE_BUS_H, 1,
			[linux/device/bus.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if bus_type remove function return void])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/device/bus.h>

		static void auxiliary_bus_remove(struct device *dev)
		{
		}
	],[
		struct bus_type btype = {
			.remove = auxiliary_bus_remove,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BUS_TYPE_REMOVE_RETURN_VOID, 1,
			[bus_type remove function return void])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if auxiliary device IRQs sysfs exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/auxiliary_bus.h>
		#include <linux/xarray.h>
	],[
		struct auxiliary_device ad;
		xa_init(&ad.sysfs.irqs);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_AUX_DEV_IRQS_SYSFS, 1,
			[auxiliary device IRQs sysfs exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blkdev.h has BLK_INTEGRITY_DEVICE_CAPABLE])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		enum  blk_integrity_flags bif = BLK_INTEGRITY_DEVICE_CAPABLE;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_INTEGRITY_DEVICE_CAPABLE, 1,
			[BLK_INTEGRITY_DEVICE_CAPABLE is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blkdev.h has BLK_MAX_WRITE_HINTS])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		int x = BLK_MAX_WRITE_HINTS;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MAX_WRITE_HINTS, 1,
			[BLK_MAX_WRITE_HINTS is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if genhd.h has device_add_disk])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		device_add_disk(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVICE_ADD_DISK, 1,
			[genhd.h has device_add_disk])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if genhd.h has device_add_disk 3 args])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		device_add_disk(NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVICE_ADD_DISK_3_ARGS_NO_RETURN, 1,
			[genhd.h has device_add_disk])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if genhd.h has device_add_disk 3 args and must_check])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		int ret;
		ret = device_add_disk(NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVICE_ADD_DISK_3_ARGS_AND_RETURN, 1,
			[genhd.h has device_add_disk 3 args and must_check])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if list_is_first is defined])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/list.h>
	],[
		list_is_first(NULL, NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_LIST_IS_FIRST, 1,
			[list_is_first is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/scatterlist.h _sg_alloc_table_from_pages has 9 params])
        MLNX_BG_LB_LINUX_TRY_COMPILE([
                #include <linux/scatterlist.h>;
	],[
		struct scatterlist *sg;

		sg = __sg_alloc_table_from_pages(NULL, NULL, 0, 0,
					    0, 0, NULL, 0, GFP_KERNEL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SG_ALLOC_TABLE_FROM_PAGES_GET_9_PARAMS, 1,
			[__sg_alloc_table_from_pages has 9 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/scatterlist.h has sg_append_table])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/scatterlist.h>
	],[
		struct sg_append_table  sgt_append;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SG_APPEND_TABLE, 1,
			[linux/scatterlist.h has sg_append_table])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/dma-resv.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/dma-resv.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DMA_RESV_H, 1,
			[linux/dma-resv.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/dma-resv.h has DMA_RESV_USAGE_KERNEL])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/dma-resv.h>
	],[
		enum dma_resv_usage usage;

		usage = DMA_RESV_USAGE_KERNEL;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DMA_RESV_USAGE_KERNEL, 1,
			[linux/dma-resv.h has DMA_RESV_USAGE_KERNEL])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/dma-resv.h has dma_resv_wait_timeout])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/dma-resv.h>
	],[
		dma_resv_wait_timeout(NULL, 0, 0, 0);
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DMA_RESV_WAIT_TIMEOUT, 1,
			[linux/dma-resv.h has dma_resv_wait_timeout])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/dma-resv.h has dma_resv_excl_fence])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/dma-resv.h>
	],[
		dma_resv_excl_fence(NULL);
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DMA_RESV_EXCL_FENCE, 1,
			[linux/dma-resv.h has dma_resv_excl_fence])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if dma_buf_dynamic_attach get 4 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/dma-buf.h>
	],[
		dma_buf_dynamic_attach(NULL, NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DMA_BUF_DYNAMIC_ATTACH_GET_4_PARAMS, 1,
			  [dma_buf_dynamic_attach get 4 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct dma_buf_attach_ops has allow_peer2peer])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/dma-buf.h>
	],[
		struct dma_buf_attach_ops x = {
			.allow_peer2peer = 0,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DMA_BUF_ATTACH_OPS_ALLOW_PEER2PEER, 1,
			  [struct dma_buf_attach_ops has allow_peer2peer])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netif_napi_add get 3 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netif_napi_add(NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_NAPI_ADD_GET_3_PARAMS, 1,
			  [netif_napi_add get 3 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has netif_napi_add_weight])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		netif_napi_add_weight(NULL, NULL, NULL ,0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_NAPI_ADD_WEIGHT, 1,
			  [netdevice.h has netif_napi_add_weight])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if bareudp.h has netif_is_bareudp])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/bareudp.h>
	],[
		netif_is_bareudp(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_IS_BAREDUDP, 1,
			  [netif_is_bareudp is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has TC_SETUP_FT])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		enum tc_setup_type x = TC_SETUP_FT;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TC_SETUP_FT, 1,
			  [TC_TC_SETUP_FT is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ib_umem_notifier_invalidate_range_start has parameter blockable])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
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
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_UMEM_NOTIFIER_PARAM_BLOCKABLE, 1,
			  [ib_umem_notifier_invalidate_range_start has parameter blockable])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if iscsit_set_unsolicited_dataout is defined])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <target/iscsi/iscsi_transport.h>
	],[
		iscsit_set_unsolicited_dataout(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ISCSIT_SET_UNSOLICITED_DATAOUT, 1,
			  [iscsit_set_unsolicited_dataout is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if mmu_notifier.h has mmu_notifier_call_srcu])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mmu_notifier.h>
	],[
		mmu_notifier_call_srcu(NULL, NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_MMU_NOTIFIER_CALL_SRCU, 1,
			  [mmu_notifier_call_srcu defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if mmu_notifier.h has mmu_notifier_synchronize])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mmu_notifier.h>
	],[
		mmu_notifier_synchronize();
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_MMU_NOTIFIER_SYNCHRONIZE, 1,
			  [mmu_notifier_synchronize defined])
	],[
		AC_MSG_RESULT(no)
	])


	AC_MSG_CHECKING([if mmu_notifier.h has mmu_notifier_range_blockable])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mmu_notifier.h>
	],[
                const struct mmu_notifier_range *range;

		mmu_notifier_range_blockable(range);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_MMU_NOTIFIER_RANGE_BLOCKABLE, 1,
			  [mmu_notifier_range_blockable defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct mmu_notifier_ops has free_notifier ])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mmu_notifier.h>
	],[
		static struct mmu_notifier_ops notifiers = {
			.free_notifier = NULL,
		};
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_MMU_NOTIFIER_OPS_HAS_FREE_NOTIFIER, 1,
			  [ struct mmu_notifier_ops has alloc/free_notifier ])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ib_umem_notifier_invalidate_range_start get struct mmu_notifier_range ])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
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
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_MMU_NOTIFIER_RANGE_STRUCT, 1,
			  [ ib_umem_notifier_invalidate_range_start get struct mmu_notifier_range ])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if mmu_notifier.h has mmu_notifier_unregister_no_release])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mmu_notifier.h>
	],[
		mmu_notifier_unregister_no_release(NULL, NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_MMU_NOTIFIER_UNREGISTER_NO_RELEASE, 1,
			  [mmu_notifier_unregister_no_release defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if have mmu interval notifier])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mmu_notifier.h>
	],[
		static struct mmu_interval_notifier_ops int_notifier_ops_xx= {
			.invalidate = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_MMU_INTERVAL_NOTIFIER, 1,
			  [mmu interval notifier defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blkdev.h has __blkdev_issue_discard])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		__blkdev_issue_discard(NULL, 0, 0, 0, 0, NULL);

		return 0;
	],[
	        AC_MSG_RESULT(yes)
	        MLNX_AC_DEFINE(HAVE___BLKDEV_ISSUE_DISCARD, 1,
	                [__blkdev_issue_discard is defined])
	],[
	        AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if __blkdev_issue_discard has 5 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		__blkdev_issue_discard(NULL, 0, 0, 0, NULL);

		return 0;
	],[
	        AC_MSG_RESULT(yes)
	        MLNX_AC_DEFINE(HAVE___BLKDEV_ISSUE_DISCARD_5_PARAM, 1,
	                [__blkdev_issue_discard has 5 params])
	],[
	        AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct bio has member bi_disk])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk_types.h>
	],[
		struct bio b = {
			.bi_disk = NULL,
		};
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BIO_BI_DISK, 1,
			[struct bio has member bi_disk])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if fs.h has stream_open])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/fs.h>
	],[
		stream_open(NULL, NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_STREAM_OPEN, 1,
			[fs.h has stream_open])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pnv-pci.h has pnv_pci_set_p2p])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <asm/pnv-pci.h>
	],[
		pnv_pci_set_p2p(NULL, NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PNV_PCI_SET_P2P, 1,
			[pnv-pci.h has pnv_pci_set_p2p])
	],[
		AC_MSG_RESULT(no)
	])

	LB_CHECK_SYMBOL_EXPORT([interval_tree_insert],
		[lib/interval_tree.c],
		[AC_DEFINE(HAVE_INTERVAL_TREE_EXPORTED, 1,
			[interval_tree functions exported by the kernel])],
	[])

	AC_MSG_CHECKING([if act_apt.h tc_setup_cb_egdev_register])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/act_api.h>
	],[
		tc_setup_cb_egdev_register(NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TC_SETUP_CB_EGDEV_REGISTER, 1,
			  [tc_setup_cb_egdev_register is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if act_api.h has tcf_action_stats_update])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/act_api.h>
	],[
		tcf_action_stats_update(NULL, 0, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TCF_ACTION_STATS_UPDATE, 1,
			  [tc_action_stats_update is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if act_api.h has tcf_action_stats_update with 5 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/act_api.h>
	],[
		tcf_action_stats_update(NULL, 0, 0, 0, true);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TCF_ACTION_STATS_UPDATE_5_PARAMS, 1,
			  [tc_action_stats_update is defined and has 5 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/uio.h has iov_iter_is_bvec])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/uio.h>
	],[
		struct iov_iter i;

		iov_iter_is_bvec(&i);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IOV_ITER_IS_BVEC_SET, 1,
				[iov_iter_is_bvec is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct xfrmdev_ops has member xdo_dev_state_add get extack])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
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
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XDO_XFRM_ADD_STATE_GET_EXTACK, 1,
			  [struct xfrmdev_ops has member xdo_dev_state_add get extack])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct xfrmdev_ops has member xdo_dev_policy_add get extack])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
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
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XDO_DEV_POLICY_ADD_GET_EXTACK, 1,
			  [struct xfrmdev_ops has member xdo_dev_policy_add get extack])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct xfrmdev_ops has member xdo_dev_policy_add])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct xfrmdev_ops x = {
			.xdo_dev_policy_add = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XDO_DEV_POLICY_ADD, 1,
			  [struct xfrmdev_ops has member xdo_dev_policy_add ])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct xfrmdev_ops has member xdo_dev_state_update_curlft])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct xfrmdev_ops x = {
			.xdo_dev_state_update_curlft = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XDO_DEV_STATE_UPDATE_CURLFT, 1,
			  [struct xfrmdev_ops has member xdo_dev_state_update_curlft ])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct xfrmdev_ops has member xdo_dev_state_update_stats])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		struct xfrmdev_ops x = {
			.xdo_dev_state_update_stats = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XDO_DEV_STATE_UPDATE_STATS, 1,
			  [struct xfrmdev_ops has member xdo_dev_state_update_stats ])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if interrupt.h has irq_affinity_desc])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/interrupt.h>
	],[
		struct irq_affinity_desc x;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IRQ_AFFINITY_DESC, 1,
			  [irq_affinity_desc is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if interrupt.h has irq_set_affinity_and_hint])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/interrupt.h>
	],[
		int x = irq_set_affinity_and_hint(0, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IRQ_UPDATE_AFFINITY_HINT, 1,
			  [irq_set_affinity_and_hint is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/overflow.h has size_add size_mul size_sub])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/overflow.h>
	],[
		size_t a = 5;
		size_t b = 6;

		if ( size_add(a,b) && size_mul(a,b) && size_sub(a,b) )
			return 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SIZE_MUL_SUB_ADD, 1,
			  [linux/overflow.h has size_add size_mul size_sub])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if function kvfree_call_rcu is defined])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/rcupdate.h>
	],[
		kvfree_call_rcu(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_KVFREE_CALL_RCU, 1,
			  [function kvfree_call_rcu is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if function kfree_rcu_mightsleep is defined])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/rcupdate.h>
	],[
		kfree_rcu_mightsleep(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_KFREE_RCU_MIGHTSLEEP, 1,
			  [function kfree_rcu_mightsleep is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/xdp.h has xdp_init_buff])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xdp.h>
	],[
		xdp_init_buff(NULL, 0, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XDP_INIT_BUFF, 1,
			  [net/xdp.h has xdp_init_buff])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/xdp.h has __xdp_rxq_info_reg])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xdp.h>
	],[
		__xdp_rxq_info_reg(NULL, NULL, 0, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_UNDERSCORE_XDP_RXQ_INFO_REG, 1,
			  [net/xdp.h has __xdp_rxq_info_reg])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/xdp.h has xdp_rxq_info_reg get 4 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xdp.h>
	],[
		xdp_rxq_info_reg(NULL, NULL, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XDP_RXQ_INFO_REG_4_PARAMS, 1,
			  [net/xdp.h has xdp_rxq_info_reg get 4 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/xdp.h struct xdp_frame_bulk exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xdp.h>
	],[
		struct xdp_frame_bulk x;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XDP_FRAME_BULK, 1,
			  [net/xdp.h struct xdp_frame_bulk exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if xdp_buff has flags as member])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xdp.h>
	],[
		struct xdp_buff x;
		x.flags = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XDP_BUFF_HAS_FLAGS, 1,
			  [xdp_buff has flags as member])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if xdp_buff has frame_sz as member])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xdp.h>
	],[
		struct xdp_buff x;
		x.frame_sz = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XDP_BUFF_HAS_FRAME_SZ, 1,
			  [xdp_buff has frame_sz as member])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/xdp.h has xdp_convert_buff_to_frame])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xdp.h>
	],[
		xdp_convert_buff_to_frame(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XDP_CONVERT_BUFF_TO_FRAME, 1,
			  [net/xdp.h has xdp_convert_buff_to_frame])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/xdp.h has convert_to_xdp_frame])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xdp.h>
	],[
		convert_to_xdp_frame(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XDP_CONVERT_TO_XDP_FRAME_IN_NET_XDP, 1,
			  [net/xdp.h has convert_to_xdp_frame])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/xdp.h has convert_to_xdp_frame workaround for 5.4.17-2011.1.2.el8uek.x86_64])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/uek_kabi.h>
		#include <net/xdp.h>
	],[
		convert_to_xdp_frame(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XDP_CONVERT_TO_XDP_FRAME_IN_UEK_KABI, 1,
			[net/xdp.h has convert_to_xdp_frame workaround for 5.4.17-2011.1.2.el8uek.x86_64])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct vfio_device_ops has iommufd support])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/vfio.h>
	],[
		struct vfio_device_ops vfio_ops = {
			.bind_iommufd = NULL,
			.unbind_iommufd = NULL,
			.attach_ioas = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SUPPORT_IOMMUFD_VFIO_PHYS_DEVICES, 1,
			  [struct vfio_device_ops has iommufd support])

	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct vfio_device_ops has detach_ioas])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/vfio.h>
	],[
		struct vfio_device_ops vfio_ops;

		vfio_ops.detach_ioas = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DETACH_IOAS_NDO, 1,
			  [struct vfio_device_ops has detach_ioas])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if has vfio_combine_iova_ranges])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/vfio.h>
	],[
		vfio_combine_iova_ranges(NULL, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VFIO_COMBINE_IOVA_RANGES, 1,
			  [has vfio_combine_iova_ranges exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if has sturct vfio_precopy_info])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/vfio.h>
	],[
		struct vfio_precopy_info info = {};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VFIO_PRECOPY_INFO, 1,
			  [sturct vfio_precopy_info exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if has vfio_pci_core_init_dev])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/vfio_pci_core.h>
	],[
		vfio_pci_core_init_dev(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VFIO_PCI_CORE_INIT, 1,
			  [vfio_pci_core_init_dev exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/vfio_pci_core.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/vfio_pci_core.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VFIO_PCI_CORE_H, 1,
			  [linux/vfio_pci_core.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/gro.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/gro.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NET_GRO_H, 1,
			  [net/gro.h is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/page_pool.h struct page_pool_params has napi as member])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/page_pool.h>
	],[
		struct page_pool_params pp = {
			.napi = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PAGE_POOL_PARAMS_NAPI_OLD, 1,
			  [net/page_pool.h struct page_pool_params has napi as member])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/page_pool/types.h struct page_pool_params has napi as member])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/page_pool/types.h>
	],[
		struct page_pool_params pp = {
			.napi = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PAGE_POOL_PARAMS_NAPI_TYPES_H, 1,
			  [net/page_pool/types.h struct page_pool_params has napi as member])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/page_pool/types.h struct page_pool_params has netdev as member])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/page_pool/types.h>
	],[
		struct page_pool_params pp = {
			.netdev = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PAGE_POOL_PARAMS_HAS_NETDEV, 1,
			  [net/page_pool/types.h struct page_pool_params has netdev as member])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/page_pool.h page_pool_get_dma_addr defined])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/page_pool.h>
	],[
		page_pool_get_dma_addr(NULL);
		page_pool_set_dma_addr(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PAGE_POOL_GET_DMA_ADDR_OLD, 1,
			  [net/page_pool.h page_pool_get_dma_addr defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/page_pool/helpers.h page_pool_get_dma_addr defined])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/page_pool/helpers.h>
	],[
		page_pool_get_dma_addr(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PAGE_POOL_GET_DMA_ADDR_HELPER, 1,
			  [net/page_pool.h page_pool_get_dma_addr defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/nexthop.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/nexthop.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NET_NEXTHOP_H, 1,
			  [net/nexthop.h is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/page_pool.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/page_pool.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NET_PAGE_POOL_OLD_H, 1,
			  [net/page_pool.h is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/page_pool/types.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/page_pool/types.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NET_PAGE_POOL_TYPES_H, 1,
			  [net/page_pool/types.h is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/page_pool.h has page_pool_release_page])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/page_pool.h>
	],[
		page_pool_release_page(NULL, NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PAGE_POOL_RELEASE_PAGE_IN_PAGE_POOL_H, 1,
			  [net/page_pool.h has page_pool_release_page])
	],[
		AC_MSG_RESULT(no)
	])


	AC_MSG_CHECKING([if net/page_pool/types.h has page_pool_release_page])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/page_pool/types.h>
	],[
		page_pool_release_page(NULL, NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PAGE_POOL_RELEASE_PAGE_IN_TYPES_H, 1,
			  [net/page_pool/types.h has page_pool_release_page])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/page_pool/types.h has page_pool_put_unrefed_page])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/page_pool/types.h>
	],[
		page_pool_put_unrefed_page(NULL, NULL, 0, false);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PAGE_POOL_PUT_UNREFED_PAGE, 1,
			  [net/page_pool/types.h has page_pool_put_unrefed_page])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/page_pool/types.h has page_pool_put_defragged_page])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/page_pool/types.h>
	],[
		page_pool_put_defragged_page(NULL, NULL, 0, false);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PAGE_POOL_DEFRAG_PAGE_IN_PAGE_POOL_TYPES_H, 1,
			  [net/page_pool/types.h has page_pool_put_defragged_page])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/page_pool.h has page_pool_put_defragged_page])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/page_pool.h>
	],[
		page_pool_put_defragged_page(NULL, NULL, 0, false);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PAGE_POOL_DEFRAG_PAGE_IN_PAGE_POOL_H, 1,
			  [net/page_pool/types.h has page_pool_put_defragged_page])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/page_pool.h has page_pool_nid_changed])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/page_pool.h>
	],[
		page_pool_nid_changed(NULL,0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PAGE_POLL_NID_CHANGED_OLD, 1,
			  [net/page_pool.h has page_pool_nid_changed])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/page_pool/helpers.h has page_pool_nid_changed])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/page_pool/helpers.h>
	],[
		page_pool_nid_changed(NULL,0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PAGE_POLL_NID_CHANGED_HELPERS, 1,
			  [net/page_pool/helpers.h has page_pool_nid_changed])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/tls.h has tls_driver_ctx])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/tls.h>
	],[
		tls_driver_ctx(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TLS_DRIVER_CTX, 1,
			  [net/tls.h has tls_driver_ctx])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/tls.h has tls_offload_rx_force_resync_request])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/tls.h>
	],[
		tls_offload_rx_force_resync_request(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TLS_OFFLOAD_RX_FORCE_RESYNC_REQUEST, 1,
			  [net/tls.h has tls_offload_rx_force_resync_request])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if have blk_queue_make_request])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		blk_queue_make_request(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_QUEUE_MAKE_REQUEST, 1,
				[blk_queue_make_request existing])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if have put_unaligned_le24])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/unaligned/generic.h>
	],[
		put_unaligned_le24(0, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PUT_UNALIGNED_LE24, 1,
				[put_unaligned_le24 existing])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([for include/linux/part_stat.h])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/part_stat.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PART_STAT_H, 1, [part_stat.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdev_bpf struct has pool member])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
		#include <net/xsk_buff_pool.h>
	],[
		struct xsk_buff_pool *x;
		struct netdev_bpf *xdp;

		xdp->xsk.pool = x;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETDEV_BPF_XSK_BUFF_POOL, 1,
			  [netdev_bpf struct has pool member])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if memremap.h has is_pci_p2pdma_page])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/memremap.h>
	],[
		is_pci_p2pdma_page(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IS_PCI_P2PDMA_PAGE_IN_MEMREMAP_H, 1,
			[is_pci_p2pdma_page is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if mm.h has gup_must_unshare get 3 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mm.h>
	],[
		gup_must_unshare(NULL, 0, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_MM_GUP_MUST_UNSHARE_GET_3_PARAMS, 1,
			[mm.h has gup_must_unshare get 3 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if mm.h has assert_fault_locked])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mm.h>
	],[
		assert_fault_locked(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ASSERT_FAULT_LOCKED, 1,
			[mm.h has assert_fault_locked])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if mm.h has is_pci_p2pdma_page])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mm.h>
	],[
		is_pci_p2pdma_page(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IS_PCI_P2PDMA_PAGE_IN_MM_H, 1,
			[is_pci_p2pdma_page is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if mm.h has release_pages])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mm.h>
	],[
		release_pages(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_RELEASE_PAGES_IN_MM_H, 1,
			[mm.h has release_pages])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if t10-pi.h has t10_pi_prepare])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/t10-pi.h>
	],[
		t10_pi_prepare(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_T10_PI_PREPARE, 1,
			[t10_pi_prepare is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blk-mq.h has busy_tag_iter_fn return bool with 2 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>

		static bool
		nvme_cancel_request(struct request *req, void *data) {
			return true;
		}
	],[
		busy_tag_iter_fn *fn = nvme_cancel_request;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MQ_BUSY_TAG_ITER_FN_BOOL_2_PARAMS, 1,
			  [linux/blk-mq.h has busy_tag_iter_fn return bool])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blk-mq.h has busy_tag_iter_fn return bool with 3 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>

		static bool
		nvme_cancel_request(struct request *req, void *data, bool reserved) {
			return true;
		}
	],[
		busy_tag_iter_fn *fn = nvme_cancel_request;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MQ_BUSY_TAG_ITER_FN_BOOL_3_PARAMS, 1,
			  [linux/blk-mq.h has busy_tag_iter_fn return bool])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct blk_mq_ops has poll 1 arg])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>

		static int nvme_poll(struct blk_mq_hw_ctx *hctx) {
			return 0;
		}
	],[
		struct blk_mq_ops ops = {
			.poll = nvme_poll,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MQ_OPS_POLL_1_ARG, 1,
			  [struct blk_mq_ops has poll 1 arg])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if bitmap.h bitmap_zalloc_node])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <linux/bitmap.h>
	],[
		unsigned long *bmap;

		bmap = bitmap_zalloc_node(1, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BITMAP_ZALLOC_NODE, 1,
		[bitmap_zalloc_node is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if dma-mapping.h has dma_map_sgtable])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/dma-mapping.h>
	],[
		int i = dma_map_sgtable(NULL, NULL, 0, 0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DMA_MAP_SGTABLE, 1,
			[dma-mapping.h has dma_map_sgtable])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if tc_htb_command has moved_qid])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/pkt_cls.h>
	],[
		struct tc_htb_qopt_offload *x;
		x->moved_qid = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TC_HTB_COMMAND_HAS_MOVED_QID, 1,
			  [struct tc_htb_command has moved_qid])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blk-mq.h has blk_mq_complete_request_sync])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		blk_mq_complete_request_sync(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MQ_COMPLETE_REQUEST_SYNC, 1,
			[blk-mq.h has blk_mq_complete_request_sync])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blk_types.h has REQ_HIPRI])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk_types.h>
	],[
		int x = REQ_HIPRI;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_TYPES_REQ_HIPRI, 1,
			  [REQ_HIPRI is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if interrupt.h has tasklet_setup])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/interrupt.h>
	],[
		tasklet_setup(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TASKLET_SETUP, 1,
			  [interrupt.h has tasklet_setup])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if dma_map_bvec exist])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
		#include <linux/dma-mapping.h>
	],[
		struct bio_vec bv = {};

		dma_map_bvec(NULL, &bv, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLKDEV_DMA_MAP_BVEC, 1,
				[dma_map_bvec exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if flow_indr_block_cb_alloc exist])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		flow_indr_block_cb_alloc(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_INDR_BLOCK_CB_ALLOC, 1,
				[flow_indr_block_cb_alloc exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct flow_block_cb exist])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		struct flow_block_cb a;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_BLOCK_CB, 1,
				[struct flow_block_cb exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/scatterlist.h sg_alloc_table_chained has nents_first_chunk parameter])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/scatterlist.h>
	],[
		sg_alloc_table_chained(NULL, 0, NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SG_ALLOC_TABLE_CHAINED_NENTS_FIRST_CHUNK_PARAM, 1,
			[sg_alloc_table_chained has nents_first_chunk parameter])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blk-mq.h has request_to_qc_t])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		request_to_qc_t(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_REQUEST_TO_QC_T, 1,
			  [linux/blk-mq.h has request_to_qc_t])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blk-mq.h has blk_mq_request_completed])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		blk_mq_request_completed(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MQ_REQUEST_COMPLETED, 1,
			  [linux/blk-mq.h has blk_mq_request_completed])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blk-mq.h has blk_mq_tagset_wait_completed_request])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		blk_mq_tagset_wait_completed_request(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MQ_TAGSET_WAIT_COMPLETED_REQUEST, 1,
			  [linux/blk-mq.h has blk_mq_tagset_wait_completed_request])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if *xpo_secure_port returns void])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/svc_xprt.h>

		void secure_port(struct svc_rqst *rqstp)
		{
			return;
		}
	],[
		struct svc_xprt_ops check_rdma_ops;

		check_rdma_ops.xpo_secure_port = secure_port;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XPO_SECURE_PORT_NO_RETURN, 1,
			[xpo_secure_port is defined and returns void])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct svc_rqst has rq_xprt_hlen])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/svc.h>
	],[
		struct svc_rqst rqst;

		rqst.rq_xprt_hlen = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SVC_RQST_RQ_XPRT_HLEN, 1,
			[struct svc_rqst has rq_xprt_hlen])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct svc_serv has sv_cb_list])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/svc.h>
	],[
		struct svc_serv serv;
		struct lwq      list;

		serv.sv_cb_list = list;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SVC_SERV_SV_CB_LIST_LWQ, 1,
			[struct svc_serv has sv_cb_list])
	],[
		AC_MSG_RESULT(no)
	])

	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/svc.h>
	],[
		struct svc_serv serv;
		struct list_head list;

		serv.sv_cb_list = list;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SVC_SERV_SV_CB_LIST_LIST_HEAD, 1,
			[struct svc_serv has sv_cb_list])
	],[
		AC_MSG_RESULT(no)
	])

	LB_CHECK_SYMBOL_EXPORT([svc_pool_wake_idle_thread],
		[net/sunrpc/svc.c],
		[AC_DEFINE(HAVE_SVC_POOL_WAKE_IDLE_THREAD, 1,
			[svc_pool_wake_idle_thread is exported by the kernel])],
	[])

	AC_MSG_CHECKING([if *send_request has 'struct rpc_rqst *req' as a param])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/xprt.h>

		int send_request(struct rpc_rqst *req)
		{
			return 0;
		}
	],[
		struct rpc_xprt_ops ops;

		ops.send_request = send_request;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XPRT_OPS_SEND_REQUEST_RQST_ARG, 1,
			[*send_request has 'struct rpc_rqst *req' as a param])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([for xprt_request_get_cong])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/xprt.h>
	],[
		return xprt_request_get_cong(NULL, NULL);
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XPRT_REQUEST_GET_CONG, 1, [get cong request])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([for "xpo_secure_port" inside "struct svc_xprt_ops"])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/svc_xprt.h>
	],[
		struct svc_xprt_ops dummy_svc_ops;

		dummy_svc_ops.xpo_secure_port = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SVC_XPRT_XPO_SECURE_PORT, 1,
			[struct svc_xprt_ops 'xpo_secure_port' field])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([for "xpo_prep_reply_hdr" inside "struct svc_xprt_ops"])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/svc_xprt.h>
	],[
		struct svc_xprt_ops dummy_svc_ops;

		dummy_svc_ops.xpo_prep_reply_hdr = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SVC_XPRT_XPO_PREP_REPLY_HDR, 1,
			[struct svc_xprt_ops 'xpo_prep_reply_hdr' field])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([for "xpo_read_payload" inside "struct svc_xprt_ops"])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/svc_xprt.h>
	],[
		struct svc_xprt_ops dummy_svc_ops;

		dummy_svc_ops.xpo_read_payload = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XPO_READ_PAYLOAD, 1,
			[struct svc_xprt_ops has 'xpo_read_payload' field])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([for "xpo_result_payload" inside "struct svc_xprt_ops"])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/svc_xprt.h>
	],[
		struct svc_xprt_ops dummy_svc_ops;

		dummy_svc_ops.xpo_result_payload = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XPO_RESULT_PAYLOAD, 1,
			[struct svc_xprt_ops has 'xpo_result_payload' field])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([for "xpo_release_ctxt" inside "struct svc_xprt_ops"])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/svc_xprt.h>
	],[
		struct svc_xprt_ops dummy_svc_ops;

		dummy_svc_ops.xpo_release_ctxt = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XPO_RELEASE_CTXT, 1,
			[struct svc_xprt_ops has 'xpo_release_ctxt' field])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([for "set_retrans_timeout" inside "struct rpc_xprt_ops"])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/xprt.h>
	],[
		struct rpc_xprt_ops dummy_ops;

		dummy_ops.set_retrans_timeout = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_RPC_XPRT_OPS_SET_RETRANS_TIMEOUT, 1,
			[struct rpc_xprt_ops has 'set_retrans_timeout' field])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([for "wait_for_reply_request" inside "struct rpc_xprt_ops"])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/xprt.h>
	],[
		struct rpc_xprt_ops dummy_ops;

		dummy_ops.wait_for_reply_request = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_RPC_XPRT_OPS_WAIT_FOR_REPLY_REQUEST, 1,
			[struct rpc_xprt_ops has 'wait_for_reply_request' field])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([for "queue_lock" inside "struct rpc_xprt"])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/xprt.h>
	],[
		spinlock_t *dummy_lock;
		struct rpc_xprt dummy_xprt;

		dummy_lock = &dummy_xprt.queue_lock;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XPRT_QUEUE_LOCK, 1,
			[struct rpc_xprt has 'queue_lock' field])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if xprt_wait_for_buffer_space has xprt as a parameter])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/xprt.h>
	],[
		struct rpc_xprt xprt = {0};

		xprt_wait_for_buffer_space(&xprt);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XPRT_WAIT_FOR_BUFFER_SPACE_RQST_ARG, 1,
			  [xprt_wait_for_buffer_space has xprt as a parameter])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([for "recv_lock" inside "struct rpc_xprt"])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/xprt.h>
	],[
		spinlock_t *dummy_lock;
		struct rpc_xprt dummy_xprt;

		dummy_lock = &dummy_xprt.recv_lock;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_RPC_XPRT_RECV_LOCK, 1, [struct rpc_xprt has 'recv_lock' field])
	],[
		AC_MSG_RESULT(no)
	])


	AC_MSG_CHECKING([for "xprt_class" inside "struct rpc_xprt"])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/xprt.h>
	],[
		struct rpc_xprt dummy_xprt;

		dummy_xprt.xprt_class = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_RPC_XPRT_XPRT_CLASS, 1, [struct rpc_xprt has 'xprt_class' field])
	],[
		AC_MSG_RESULT(no)
	])

	LB_CHECK_SYMBOL_EXPORT([xprt_reconnect_delay],
		[net/sunrpc/xprt.c],
		[AC_DEFINE(HAVE_XPRT_RECONNECT_DELAY, 1,
			[xprt_reconnect_delay is exported by the kernel])],
	[])

	AC_MSG_CHECKING([for "bc_num_slots" inside "struct rpc_xprt_ops"])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/xprt.h>
	],[
		struct rpc_xprt_ops dummy_ops;

		dummy_ops.bc_num_slots = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_RPC_XPRT_OPS_BC_NUM_SLOTS, 1,
			[struct rpc_xprt_ops has 'bc_num_slots' field])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([for "bc_up" inside "struct rpc_xprt_ops"])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/xprt.h>
	],[
		struct rpc_xprt_ops dummy_ops;

		dummy_ops.bc_up = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_RPC_XPRT_OPS_BC_UP, 1,
			[struct rpc_xprt_ops has 'bc_up' field])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([for "netid" inside "struct xprt_class"])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/xprt.h>
	],[
		struct xprt_class xc;

		xc.netid;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XPRT_CLASS_NETID, 1,
			[struct xprt_class has 'netid' field])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/sysctl.h has SYSCTL_ZERO])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sysctl.h>
	],[
		void *dummy;

		dummy = SYSCTL_ZERO;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SYSCTL_ZERO_ENABLED, 1,
			[linux/sysctl.h has SYSCTL_ZERO defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([for "child" field inside "struct ctl_table"])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sysctl.h>
	],[
		 struct ctl_table dummy_table;

		dummy_table.child = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_CTL_TABLE_CHILD, 1,
			[struct ctl_table have "child" field] )
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if defined XDRBUF_SPARSE_PAGES])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/xdr.h>
	],[
		int dummy;

		dummy = XDRBUF_SPARSE_PAGES;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XDRBUF_SPARSE_PAGES, 1,
			  [XDRBUF_SPARSE_PAGES has defined in linux/sunrpc/xdr.h])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if xdr_init_encode has rqst as a parameter])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/xdr.h>
	],[
		struct rpc_rqst *rqst = NULL;

		xdr_init_encode(NULL, NULL, NULL, rqst);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XDR_INIT_ENCODE_RQST_ARG, 1,
			  [xdr_init_encode has rqst as a parameter])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if xdr_init_decode has rqst as a parameter])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/xdr.h>
	],[
		struct rpc_rqst *rqst = NULL;

		xdr_init_decode(NULL, NULL, NULL, rqst);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XDR_INIT_DECODE_RQST_ARG, 1,
			  [xdr_init_decode has rqst as a parameter])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([for "rc_stream" inside "struct svc_rdma_recv_ctxt"])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/xdr.h>
		#include <linux/sunrpc/svc_rdma.h>
	],[
		struct xdr_stream dummy_stream;
		struct svc_rdma_recv_ctxt dummy_rctxt;

		dummy_rctxt.rc_stream = dummy_stream;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SVC_RDMA_RECV_CTXT_RC_STREAM, 1,
			[struct svc_rdma_recv_ctxt has 'rc_stream' field])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([for "sc_pending_recvs" inside "struct svcxprt_rdma"])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/svc_rdma.h>
	],[
		struct svcxprt_rdma dummy_rdma;

		dummy_rdma.sc_pending_recvs = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SVCXPRT_RDMA_SC_PENDING_RECVS, 1,
			[struct svcxprt_rdma has 'sc_pending_recvs' field])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if xdr_encode_rdma_segment has defined])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/xdr.h>
		#include <linux/sunrpc/rpc_rdma.h>
	],[
		xdr_encode_rdma_segment(NULL, 0, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XDR_ENCODE_RDMA_SEGMENT, 1,
			  [xdr_encode_rdma_segment has defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if xdr_decode_rdma_segment has defined])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/xdr.h>
		#include <linux/sunrpc/rpc_rdma.h>
	],[
		xdr_decode_rdma_segment(NULL, 0, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XDR_DECODE_RDMA_SEGMENT, 1,
			  [xdr_decode_rdma_segment has defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if xdr_stream_encode_item_absent has defined])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/xdr.h>
	],[
		xdr_stream_encode_item_absent(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XDR_STREAM_ENCODE_ITEM_ABSENT, 1,
			  [xdr_stream_encode_item_absent has defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if xdr_item_is_absent has defined])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/xdr.h>
	],[
		xdr_item_is_absent(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XDR_ITEM_IS_ABSENT, 1,
			  [xdr_item_is_absent has defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if xdr_buf_subsegment get const])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/xdr.h>
	],[
		const struct xdr_buf *dummy;
		xdr_buf_subsegment(dummy, NULL, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XDR_BUF_SUBSEGMENT_CONST, 1,
			  [xdr_buf_subsegment get const])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if svc_xprt_is_dead has defined])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/svc_xprt.h>
	],[
		svc_xprt_is_dead(NULL);

        return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SVC_XPRT_IS_DEAD, 1,
			  [svc_xprt_is_dead has defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if svc_rdma_release_rqst has externed])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/svc_rdma.h>
	],[
		svc_rdma_release_rqst(NULL);

        return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SVC_RDMA_RELEASE_RQST, 1,
			  [svc_rdma_release_rqst has externed])
	],[
		AC_MSG_RESULT(no)
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

	AC_MSG_CHECKING([for trace/events/rpcrdma.h])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/svc_rdma.h>
		#include "../../net/sunrpc/xprtrdma/xprt_rdma.h"

		#include <trace/events/rpcrdma.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TRACE_RPCRDMA_H, 1, [rpcrdma.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([for struct svc_rdma_pcl])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sunrpc/xdr.h>
		#include <linux/sunrpc/svc_rdma_pcl.h>
	],[
		struct svc_rdma_pcl *pcl;

		pcl = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SVC_RDMA_PCL, 1, [struct svc_rdma_pcl exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if class_create get 1 param])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/device/class.h>
	],[
	        static struct class *uverbs_class;
		uverbs_class = class_create("Test");

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_CLASS_CREATE_GET_1_PARAM, 1,
			  [class_create get 1 param])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if show_class_attr_string get const])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/device/class.h>
	],[
	        const struct class *uverbs_class;
	        const struct class_attribute *uverbs_attr;

		show_class_attr_string(uverbs_class, uverbs_attr, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SHOW_CLASS_ATTR_STRING_GET_CONST, 1,
			  [show_class_attr_string get const])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if class_register takes a const param])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/device/class.h>
	],[
	        const struct class *c = NULL;

		class_register(c);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_CLASS_REGISTER_GET_CONST, 1,
			  [class_register get const])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netdevice.h has __netdev_tx_sent_queue])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/netdevice.h>
	],[
		__netdev_tx_sent_queue(NULL, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE___NETDEV_TX_SENT_QUEUE, 1,
			  [netdevice.h has __netdev_tx_sent_queue])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if msi_map exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/msi_api.h>
	],[
		struct msi_map x;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_MSI_MAP_TMP, 1,
			  [msi_map exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if flow_dissector.h enum flow_dissector_key_keyid has FLOW_DISSECTOR_KEY_META])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_dissector.h>
	],[
		enum flow_dissector_key_id keyid = FLOW_DISSECTOR_KEY_META;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_DISSECTOR_KEY_META, 1,
			  [FLOW_DISSECTOR_KEY_META is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netif_is_geneve exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <uapi/linux/if.h>
		#include <net/geneve.h>
	],[
		netif_is_geneve(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_IS_GENEVE, 1,
			  [netif_is_geneve is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if have netif_is_gretap])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <uapi/linux/if.h>
		#include <net/gre.h>
	],[
		struct net_device dev = {};

		netif_is_gretap(&dev);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_IS_GRETAP, 1,
			  [netif_is_gretap is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if have netif_is_vxlan])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/vxlan.h>
	],[
		struct net_device dev = {};

		netif_is_vxlan(&dev);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_IS_VXLAN, 1,
			  [netif_is_vxlan is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if uapi/linux/mei_uuid.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <uapi/linux/mei_uuid.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_LINUX_MEI_UUID_H, 1,
			  [uapi/linux/mei_uuid.h is exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/bareudp.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/bareudp.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NET_BAREUDP_H, 1,
			  [net/bareudp.h is exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/psample.h has struct psample_metadata])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
		#include <net/psample.h>
	],[
		struct psample_metadata *x;
		x->trunc_size = 0;

		return 0
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_STRUCT_PSAMPLE_METADATA, 1,
			      [net/psample.h has struct psample_metadata])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if netif_is_bareudp exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/bareudp.h>
	],[
		netif_is_bareudp(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NETIF_IS_BAREUDP, 1,
			  [netif_is_bareudp is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blkdev.h has req_bvec])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
		#include <linux/blk-mq.h>
	],[
		req_bvec(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLKDEV_REQ_BVEC, 1,
				[linux/blkdev.h has req_bvec])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci-p2pdma.h has pci_p2pdma_map_sg_attrs])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci-p2pdma.h>
	],[
		pci_p2pdma_map_sg_attrs(NULL, NULL, 0, 0, 0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_P2PDMA_MAP_SG_ATTRS, 1,
			  [pci_p2pdma_map_sg_attrs defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if uapi/linux/nvme_ioctl.h has struct nvme_passthru_cmd64])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/nvme_ioctl.h>
		#include <linux/types.h>
		#include <uapi/asm-generic/ioctl.h>
	],[
		struct nvme_passthru_cmd64 cmd = {};
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_UAPI_LINUX_NVME_PASSTHRU_CMD64, 1,
			[uapi/linux/nvme_ioctl.h has struct nvme_passthru_cmd64])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct request_queue has backing_dev_info])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		struct backing_dev_info *bdi = NULL;
		struct request_queue rq = {
			.backing_dev_info = bdi,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_REQUEST_QUEUE_BACKING_DEV_INFO, 1,
			  [struct request_queue has backing_dev_info])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/skbuff.h has skb_queue_empty_lockless])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		skb_queue_empty_lockless(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SKB_QUEUE_EMPTY_LOCKLESS, 1,
			  [linux/skbuff.h has skb_queue_empty_lockless])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct pci_driver has member driver_managed_dma])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		struct pci_driver core_driver = {
			.driver_managed_dma = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_DRIVER_MANAGED_DMA, 1,
			[struct pci_driver has member driver_managed_dma])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/pci.h has pcie_aspm_enabled])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		pcie_aspm_enabled(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCIE_ASPM_ENABLED, 1,
			[linux/pci.h has pcie_aspm_enabled])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/macsec.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/macsec.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_MACSEC_H, 1,
			  [net/macsec.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/xdp_sock_drv.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xdp_sock_drv.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XDP_SOCK_DRV_H, 1,
			  [net/xdp_sock_drv.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if xsk_buff_dma_sync_for_cpu get 2 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xdp_sock_drv.h>
	],[
		xsk_buff_dma_sync_for_cpu(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XSK_BUFF_DMA_SYNC_FOR_CPU_2_PARAMS, 1,
			  [xsk_buff_dma_sync_for_cpu get 2 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if include/linux/units.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/units.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_UNITS_H, 1,
			  [include/linux/units.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if v6.6 remove sentinel from ctl_table array is supported])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sysctl.h>
	],[
		struct ctl_table_header cth;

		cth.ctl_table_size = 1;
		register_sysctl_sz(NULL, NULL, 1);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_REMOVE_SENTINEL_FROM_CTL_TABLE, 1,
			  [v6.6 remove sentinel from ctl_table array is supported])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if proc_handler have const parameter])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/sysctl.h>
	],[
		struct ctl_table dummy_table;
		const struct ctl_table *ctl = &dummy_table;

		dummy_table.proc_handler(ctl, 0, NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PROC_HANDLER_CONST_PARAM, 1,
			  [proc_handler has const parameter])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blkdev.h has bio_integrity_bytes])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		bio_integrity_bytes(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLKDEV_BIO_INTEGRITY_BYTES, 1,
				[linux/blkdev.h has bio_integrity_bytes])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if include/net/esp.h has esp_output_fill_trailer])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xfrm.h>
		#include <net/esp.h>
	],[
		esp_output_fill_trailer(NULL, 0, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ESP_OUTPUT_FILL_TRAILER, 1,
			  [esp_output_fill_trailer is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blk_queue_max_active_zones exist])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		blk_queue_max_active_zones(NULL, 0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_QUEUE_MAX_ACTIVE_ZONES, 1,
				[blk_queue_max_active_zones exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if genhd.h has set_capacity_revalidate_and_notify])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		set_capacity_revalidate_and_notify(NULL, 0, false);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SET_CAPACITY_REVALIDATE_AND_NOTIFY, 1,
			[genhd.h has set_capacity_revalidate_and_notify])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct block_device_operations has submit_bio])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		struct block_device_operations ops = {
			.submit_bio = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLOCK_DEVICE_OPERATIONS_SUBMIT_BIO, 1,
			  [struct block_device_operations has submit_bio])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blk_queue_split has 1 param])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		blk_queue_split(NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_QUEUE_SPLIT_1_PARAM, 1,
				[blk_queue_split has 1 param])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blkdev.h has bio_split_to_limits])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		bio_split_to_limits(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BIO_SPLIT_TO_LIMITS, 1,
				[blkdev.h has bio_split_to_limits])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if submit_bio_noacct exist])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		submit_bio_noacct(NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SUBMIT_BIO_NOACCT, 1,
				[submit_bio_noacct exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blk-mq.h has blk_should_fake_timeout])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		blk_should_fake_timeout(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_SHOULD_FAKE_TIMEOUT, 1,
			  [linux/blk-mq.h has blk_should_fake_timeout])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blk-mq.h has blk_mq_complete_request_remote])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		blk_mq_complete_request_remote(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MQ_COMPLETE_REQUEST_REMOTE, 1,
			  [linux/blk-mq.h has blk_mq_complete_request_remote])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if trace_block_bio_complete has 2 param])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <trace/events/block.h>
	],[
		trace_block_bio_complete(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TRACE_BLOCK_BIO_COMPLETE_2_PARAM, 1,
			  [trace_block_bio_complete has 2 param])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/ip.h has ip_sock_set_tos])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/ip.h>
	],[
		ip_sock_set_tos(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IP_SOCK_SET_TOS, 1,
			  [net/ip.h has ip_sock_set_tos])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/tcp.h has skb_tcp_all_headers])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/tcp.h>
	],[
		skb_tcp_all_headers(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SKB_TCP_ALL_HEADERS, 1,
			  [linux/tcp.h has skb_tcp_all_headers])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/tcp.h has tcp_sock_set_syncnt])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/tcp.h>
	],[
		tcp_sock_set_syncnt(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TCP_SOCK_SET_SYNCNT, 1,
			  [linux/tcp.h has tcp_sock_set_syncnt])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/tcp.h has tcp_sock_set_nodelay])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/tcp.h>
	],[
		tcp_sock_set_nodelay(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TCP_SOCK_SET_NODELAY, 1,
			  [linux/tcp.h has tcp_sock_set_nodelay])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blkdev_issue_flush has 2 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		blkdev_issue_flush(NULL, 0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLKDEV_ISSUE_FLUSH_2_PARAM, 1,
				[blkdev_issue_flush has 2 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/sock.h has sock_no_linger])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/sock.h>
	],[
		sock_no_linger(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SOCK_NO_LINGER, 1,
			  [net/sock.h has sock_no_linger])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/sock.h has sock_set_priority])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/sock.h>
	],[
		sock_set_priority(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SOCK_SET_PRIORITY, 1,
			  [net/sock.h has sock_set_priority])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/sock.h has sock_set_reuseaddr])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/sock.h>
	],[
		sock_set_reuseaddr(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SOCK_SET_REUSEADDR, 1,
			  [net/sock.h has sock_set_reuseaddr])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/net.h has sendpage_ok])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/net.h>
	],[
		sendpage_ok(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SENDPAGE_OK, 1,
			[linux/net.h has sendpage_ok])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if ptp_find_pin_unlocked is defined])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ptp_clock_kernel.h>
	],[
		ptp_find_pin_unlocked(NULL, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PTP_FIND_PIN_UNLOCK, 1,
			  [ptp_find_pin_unlocked is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if uapi/linux/xfrm.h has XFRM_OFFLOAD_PACKET])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <uapi/linux/xfrm.h>
	],[
		int a = XFRM_OFFLOAD_PACKET;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XFRM_OFFLOAD_PACKET, 1,
			  [XFRM_OFFLOAD_PACKET is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct xfrm_offload has inner_ipproto])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/xfrm.h>
	],[
		struct xfrm_offload xo = {
			.inner_ipproto = 4,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_XFRM_OFFLOAD_INNER_IPPROTO, 1,
			  [struct xfrm_offload has inner_ipproto])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if genhd.h has bd_set_nr_sectors])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		bd_set_nr_sectors(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BD_SET_NR_SECTORS, 1,
			  [genhd.h has bd_set_nr_sectors])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blkdev.h has QUEUE_FLAG_STABLE_WRITES])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		int x = QUEUE_FLAG_STABLE_WRITES;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_QUEUE_FLAG_STABLE_WRITES, 1,
			[QUEUE_FLAG_STABLE_WRITES is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if genhd.h has revalidate_disk_size])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		revalidate_disk_size(NULL, false);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_REVALIDATE_DISK_SIZE, 1,
			  [genhd.h has revalidate_disk_size])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blk-mq.h has blk_mq_set_request_complete])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		blk_mq_set_request_complete(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MQ_SET_REQUEST_COMPLETE, 1,
			  [linux/blk-mq.h has blk_mq_set_request_complete])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blkdev.h has blk_alloc_queue_rh])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		blk_alloc_queue_rh(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_ALLOC_QUEUE_RH, 1,
				[linux/blkdev.h has blk_alloc_queue_rh])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blkdev.h struct request has block_device])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
		#include <linux/blk-mq.h>
	],[
		struct block_device *bdev = NULL;
		struct request rq = { .part = bdev };
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_REQUEST_BDEV, 1,
			[blkdev.h struct request has block_device])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blkdev_issue_flush has 1 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		blkdev_issue_flush(NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLKDEV_ISSUE_FLUSH_1_PARAM, 1,
			[blkdev_issue_flush has 1 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if bio.h has bio_max_segs])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/bio.h>
	],[
		bio_max_segs(0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BIO_MAX_SEGS, 1,
			[if bio.h has bio_max_segs])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if trace_block_bio_remap has 4 param])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <trace/events/block.h>
	],[
		trace_block_bio_remap(NULL, NULL, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TRACE_BLOCK_BIO_REMAP_4_PARAM, 1,
			[trace_block_bio_remap has 4 param])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if genhd.h has bd_set_size])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		bd_set_size(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BD_SET_SIZE, 1,
			[genhd.h has bd_set_size])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blk_execute_rq_nowait has 5 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		blk_execute_rq_nowait(NULL, NULL, NULL, 0, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_EXECUTE_RQ_NOWAIT_5_PARAM, 1,
				[blk_execute_rq_nowait has 5 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blk_execute_rq_nowait has 3 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		blk_execute_rq_nowait(NULL, 0, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_EXECUTE_RQ_NOWAIT_3_PARAM, 1,
				[blk_execute_rq_nowait has 3 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blk_execute_rq_nowait has 2 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		blk_execute_rq_nowait(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_EXECUTE_RQ_NOWAIT_2_PARAM, 1,
				[blk_execute_rq_nowait has 2 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blk_execute_rq has 4 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		blk_execute_rq(NULL, NULL, NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_EXECUTE_RQ_4_PARAM, 1,
				[blk_execute_rq  has 4 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct enum has member BIO_REMAPPED])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk_types.h>
	],[
		int tmp = BIO_REMAPPED;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ENUM_BIO_REMAPPED, 1,
			[struct enum has member BIO_REMAPPED])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct pci_driver has member sriov_get_vf_total_msix/sriov_set_msix_vec_count])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		struct pci_driver core_driver = {
			.sriov_get_vf_total_msix = NULL,
			.sriov_set_msix_vec_count = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SRIOV_GET_SET_MSIX_VEC_COUNT, 1,
			[struct pci_driver has member sriov_get_vf_total_msix/sriov_set_msix_vec_count])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct bio has member bi_bdev])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <linux/blk_types.h>
	],[
		struct bio b = {
			.bi_bdev = NULL,
		};
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BIO_BI_BDEV, 1,
			  [struct bio has member bi_bdev])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if genhd.h has bdev_nr_sectors])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		bdev_nr_sectors(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BDEV_NR_SECTORS, 1,
				[genhd.h has bdev_nr_sectors])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if BLK_STS_ZONE_ACTIVE_RESOURCE is defined in blk_types])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk_types.h>
	],[
		blk_status_t error = BLK_STS_ZONE_ACTIVE_RESOURCE;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MQ_BLK_STS_ZONE_ACTIVE_RESOURCE, 1,
				[blk_types.h has BLK_STS_ZONE_ACTIVE_RESOURCE])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if dma-mapping.h has dma_set_min_align_mask])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/dma-mapping.h>
	],[
		dma_set_min_align_mask(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DMA_SET_MIN_ALIGN_MASK, 1,
				[dma_set_min_align_mask is defined in dma-mapping])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if bio.h has bio_for_each_bvec])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		  #include <linux/bio.h>
	],[
		  struct bio *bio;
		  struct bvec_iter bi;
		  struct bio_vec bv;

		  bio_for_each_bvec(bv, bio, bi);

		  return 0;
	],[
		  AC_MSG_RESULT(yes)
		  MLNX_AC_DEFINE(HAVE_BIO_FOR_EACH_BVEC, 1,
			    [bio_for_each_bvec is defined in bio.h])
	],[
		  AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blk-mq.h has blk_mq_hctx_set_fq_lock_class])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		blk_mq_hctx_set_fq_lock_class(NULL, NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MQ_HCTX_SET_FQ_LOCK_CLASS, 1,
			[blk-mq.h has blk_mq_hctx_set_fq_lock_class])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if bio.h has BIO_MAX_VECS])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/bio.h>
	],[
		int x = BIO_MAX_VECS;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BIO_MAX_VECS, 1,
			[if bio.h has BIO_MAX_VECS])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blk-mq.h has blk_rq_bio_prep])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		blk_rq_bio_prep(NULL, NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_RQ_BIO_PREP, 1,
			[if blk-mq.h has blk_rq_bio_prep])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if genhd.h has blk_alloc_disk with 1 param])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
                #include <linux/blkdev.h>
	],[
		blk_alloc_disk(0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_ALLOC_DISK_1_PARAM, 1,
				[genhd.h has blk_alloc_disk])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if asm-generic/unaligned.h has put_unaligned_le24])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <asm-generic/unaligned.h>
	],[
		put_unaligned_le24(0, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PUT_UNALIGNED_LE24_ASM_GENERIC, 1,
				[put_unaligned_le24 existing in asm-generic/unaligned.h])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if genhd.h has GENHD_FL_UP])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		int x = GENHD_FL_UP;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GENHD_FL_UP, 1,
			  [genhd.h has GENHD_FL_UP])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blk-mq.h has blk_mq_alloc_disk 2 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		blk_mq_alloc_disk(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MQ_ALLOC_DISK_2_PARAMS, 1,
			  [blk_mq_alloc_disk is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct blk_mq_ops has poll 2 args])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
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
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MQ_OPS_POLL_2_ARG, 1,
			  [struct blk_mq_ops has poll 2 args])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct bio has member bi_cookie])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk_types.h>
	],[
		struct bio b = {
			.bi_cookie = 0,
		};
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BIO_BI_COOKIE, 1,
			[struct bio has member bi_cookie])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if genhd.h has device_add_disk retrun])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		int ret = device_add_disk(NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVICE_ADD_DISK_RETURN, 1,
			[genhd.h has device_add_disk retrun])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/fs.h has struct kiocb ki_complete 2 args])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/fs.h>

		static void func(struct kiocb *iocb, long ret) {
			return;
		}
	],[
		struct kiocb x = {
			.ki_complete = func,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FS_KIOCB_KI_COMPLETE_2_ARG, 1,
			[linux/fs.h has struct kiocb ki_complete 2 args])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blk_execute_rq has 2 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		blk_execute_rq(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_EXECUTE_RQ_2_PARAM, 1,
				[blk_execute_rq has 2 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if genhd.h has GENHD_FL_EXT_DEVT])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		int x = GENHD_FL_EXT_DEVT;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GENHD_FL_EXT_DEVT, 1,
			  [genhd.h has GENHD_FL_EXT_DEVT])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blk-mq.h struct request has rq_disk])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		struct request rq = { .rq_disk = NULL };
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_REQ_RQ_DISK, 1,
			[blkdev.h struct request has rq_disk])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct blk_mq_ops has queue_rqs])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		struct blk_mq_ops ops = {
			.queue_rqs = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MQ_OPS_QUEUE_RQS, 1,
			  [struct blk_mq_ops has queue_rqs])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if bdev_nr_bytes exist])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		bdev_nr_bytes(NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BDEV_NR_BYTES, 1,
			[bdev_nr_bytes exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci_ids.h has PCI_VENDOR_ID_REDHAT])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci_ids.h>
	],[
		int x = PCI_VENDOR_ID_REDHAT;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_VENDOR_ID_REDHAT, 1,
			  [PCI_VENDOR_ID_REDHAT is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if acpi_storage_d3 exist])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/acpi.h>
	],[
		acpi_storage_d3(NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ACPI_STORAGE_D3, 1,
			[acpi_storage_d3 exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/moduleparam.h has param_set_uint_minmax])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/moduleparam.h>
	],[
		param_set_uint_minmax(NULL, NULL, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PARAM_SET_UINT_MINMAX, 1,
			[linux/moduleparam.h has param_set_uint_minmax])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blk-mq.h has blk_mq_wait_quiesce_done])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		blk_mq_wait_quiesce_done(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MQ_WAIT_QUIESCE_DONE, 1,
			  [blk_mq_wait_quiesce_done is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blk-mq.h has blk_mq_wait_quiesce_done with tagset param])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		struct blk_mq_tag_set set = {0};

		blk_mq_wait_quiesce_done(&set);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MQ_WAIT_QUIESCE_DONE_TAGSET, 1,
			  [blk_mq_wait_quiesce_done with tagset param is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if timeout from struct blk_mq_ops has 1 param])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
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
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MQ_OPS_TIMEOUT_1_PARAM, 1,
			  [timeout from struct blk_mq_ops has 1 param])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blk-mq.h has blk_mq_destroy_queue])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		blk_mq_destroy_queue(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MQ_DESTROY_QUEUE, 1,
			  [blk_mq_destroy_queue is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blk_execute_rq has 3 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
		#include <linux/blkdev.h>
	],[
		blk_status_t x = blk_execute_rq(NULL, NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_EXECUTE_RQ_3_PARAM, 1,
				[blk_execute_rq has 3 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if disk_uevent exist])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		disk_uevent(NULL, 0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DISK_UEVENT, 1,
			[disk_uevent exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blk-cgroup.h has FC_APPID_LEN])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-cgroup.h>
	],[
		int x = FC_APPID_LEN;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FC_APPID_LEN, 1,
			  [FC_APPID_LEN is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/bvec.h has bvec_virt])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/bio.h>
		#include <linux/bvec.h>
	],[
		bvec_virt(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BVEC_VIRT, 1,
			[linux/bvec.h has bvec_virt])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/sock.h has sock_setsockopt sockptr_t])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/sock.h>
	],[
		sockptr_t optval = {};

		sock_setsockopt(NULL, 0, 0, optval, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SOCK_SETOPTVAL_SOCKPTR_T, 1,
			  [net/sock.h has sock_setsockopt sockptr_t])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if bio.h blk_next_bio has 3 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/bio.h>
	],[
		blk_next_bio(NULL, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_NEXT_BIO_3_PARAMS, 1,
			  [bio.h blk_next_bio has 3 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if disk_update_readahead exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		disk_update_readahead(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DISK_UPDATE_READAHEAD, 1,
			[disk_update_readahead exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/vmalloc.h has __vmalloc 3 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/vmalloc.h>
	],[
		__vmalloc(0, 0, PAGE_KERNEL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_VMALLOC_3_PARAM, 1,
			[linux/vmalloc.h has __vmalloc 3 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if bio.h bio_init has 5 parameters])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/bio.h>
	],[
		bio_init(NULL, NULL, NULL, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BIO_INIT_5_PARAMS, 1,
			  [bio.h bio_init has 5 parameters])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if bio.h has bio_add_zone_append_page])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/bio.h>
	],[
		bio_add_zone_append_page(NULL, NULL, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BIO_ADD_ZONE_APPEND_PAGE, 1,
			[bio.h has bio_add_zone_append_page])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blkdev.h has blk_cleanup_disk()])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		struct gendisk *disk;

		blk_cleanup_disk(disk);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_CLEANUP_DISK, 1,
			[blk_cleanup_disk() is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct gendisk has conv_zones_bitmap])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		struct gendisk disk;

		disk.conv_zones_bitmap = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GENDISK_CONV_ZONES_BITMAP, 1,
			[struct gendisk has conv_zones_bitmap])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blkdev.h has bdev_nr_zones])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		bdev_nr_zones(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BDEV_NR_ZONES, 1,
			[blkdev.h has bdev_nr_zones])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blkdev.h has blk_queue_zone_sectors])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		blk_queue_zone_sectors(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_QUEUE_ZONE_SECTORS, 1,
			[blkdev.h has blk_queue_zone_sectors])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if uapi/linux/ptp_clock.h has PTP_PEROUT_DUTY_CYCLE])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <uapi/linux/ptp_clock.h>
	],[
		int x = PTP_PEROUT_DUTY_CYCLE;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PTP_PEROUT_DUTY_CYCLE, 1,
			[PTP_PEROUT_DUTY_CYCLE is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/dst_metadata.h has struct macsec_info])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/dst_metadata.h>
	],[
		struct macsec_info info = {};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_STRUCT_MACSEC_INFO_METADATA, 1,
			      [net/dst_metadata.h has struct macsec_info])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/macsec.c has function macsec_get_real_dev])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/macsec.h>
	],[
		macsec_get_real_dev(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FUNC_MACSEC_GET_REAL_DEV, 1,
			      [net/macsec.c has function macsec_get_real_dev])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if macsec_ops has boolean field rx_uses_md_dst])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/macsec.h>
	],[
		struct macsec_ops ops;
		ops.rx_uses_md_dst = true;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_RX_USES_MD_DST_IN_MACSEC_OPS, 1,
			      [macsec_ops has boolean field rx_uses_md_dst])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if flow_dissector.h has FLOW_DISSECTOR_F_STOP_BEFORE_ENCAP])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_dissector.h>
	],[
		int x = FLOW_DISSECTOR_F_STOP_BEFORE_ENCAP;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_DISSECTOR_F_STOP_BEFORE_ENCAP, 1,
			  [FLOW_DISSECTOR_F_STOP_BEFORE_ENCAP is defined])
	],[
		AC_MSG_RESULT(no)
	])

	LB_CHECK_SYMBOL_EXPORT([rpc_task_gfp_mask],
		[net/sunrpc/sched.c],
		[AC_DEFINE(HAVE_RPC_TASK_GPF_MASK_EXPORTED, 1,
			[rpc_task_gfp_mask is exported by the kernel])],
	[])

	AC_MSG_CHECKING([if net/macsec.c has function macsec_netdev_is_offloaded])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/macsec.h>
	],[
		macsec_netdev_is_offloaded(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FUNC_MACSEC_NETDEV_IS_OFFLOADED, 1,
			      [net/macsec.c has function macsec_netdev_is_offloaded])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/macsec.h has function macsec_netdev_priv])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/macsec.h>
	],[
		macsec_netdev_priv(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FUNC_MACSEC_NETDEV_PRIV, 1,
			      [net/macsec.h has function macsec_netdev_priv])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct macsec_context has update_pn])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/macsec.h>
	],[
		struct macsec_context ctx;
		ctx.sa.update_pn = 0;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_STRUCT_MACSEC_CONTEXT_UPDATE_PN, 1,
			      [struct macsec_context has update_pn])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/fs.h struct file_operations has uring_cmd])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/fs.h>
	],[
		struct file_operations xx = {
			.uring_cmd = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FILE_OPERATIONS_URING_CMD, 1,
			[uring_cmd is defined in file_operations])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blkdev.h has function disk_set_zoned])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		disk_set_zoned(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DISK_SET_ZONED, 1,
			[disk_set_zoned is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if uapi/linux/nvme_ioctl.h has NVME_IOCTL_IO64_CMD_VEC])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/nvme_ioctl.h>
		#include <asm-generic/ioctl.h>
	],[
		unsigned int x = NVME_IOCTL_IO64_CMD_VEC;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NVME_IOCTL_IO64_CMD_VEC, 1,
			[NVME_IOCTL_IO64_CMD_VEC is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/t10-pi.h has ext_pi_ref_tag])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/t10-pi.h>
	],[
		ext_pi_ref_tag(NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_EXT_PI_REF_TAG, 1,
			[ext_pi_ref_tag is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blk_types.h has blk_opf_t])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk_types.h>
	],[
		blk_opf_t xx;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_OPF_T, 1,
			[blk_opf_t is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/fs.h sruct file has f_iocb_flags])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/fs.h>
	],[
		struct file f = {
			.f_iocb_flags = 0,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FILE_F_IOCB_FLAGS, 1,
			[sruct file has f_iocb_flags])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blkdev.h has bdev_max_zone_append_sectors])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		bdev_max_zone_append_sectors(NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BDEV_MAX_ZONE_APPEND_SECTORS, 1,
			[blkdev.h has bdev_max_zone_append_sectors])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if file linux/blk-mq.h has enum rq_end_io_ret])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		enum rq_end_io_ret x;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_RQ_END_IO_RET, 1,
			[if file rq_end_io_ret exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if function map_queues returns int])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		int foo(struct blk_mq_tag_set *x) {
			return 0;
		}

		struct blk_mq_ops ops = {
			.map_queues = foo,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MQ_OPS_MAP_QUEUES_RETURN_INT, 1,
			  [function map_queues returns int])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blk-cgroup has blkcg_get_fc_appid])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-cgroup.h>
	],[
		blkcg_get_fc_appid(NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLKCG_GET_FC_APPID, 1,
			[blkcg_get_fc_appid is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blkdev.h has blkdev_compat_ptr_ioctl])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		blkdev_compat_ptr_ioctl(NULL, 0, 0, 0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLKDEV_COMPAT_PTR_IOCTL, 1,
			[blkdev_compat_ptr_ioctl is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/vxlan.h has VXLAN_GBP_MASK])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/vxlan.h>
	],[
		uint32_t gbp_mask = VXLAN_GBP_MASK;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_CHECK_VXLAN_GBP_MASK, 1,
			[VXLAN_GBP_MASK is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct tc_skb_ext has act_miss])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/skbuff.h>
	],[
		struct tc_skb_ext ext = {};

		ext.act_miss = 1;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TC_SKB_EXT_ACT_MISS, 1,
			  [linux/skbuff.h struct tc_skb_ext has act-miss])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if net/vxlan.h has vxlan_build_gbp_hdr])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/vxlan.h>
	],[
		vxlan_build_gbp_hdr(NULL, NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_CHECK_VXLAN_BUILD_GBP_HDR, 1,
			[vxlan_build_gbp_hdr is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct flow_action_entry has hw_index])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		struct flow_action_entry ent = {};

		ent.hw_index = 0;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_ACTION_ENTRY_HW_INDEX, 1,
			  [net/flow_offload.h struct flow_action_entry has hw_index])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct flow_action_entry has miss_cookie])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		struct flow_action_entry ent = {};

		ent.miss_cookie = 0;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_ACTION_ENTRY_MISS_COOKIE, 1,
			  [net/flow_offload.h struct flow_action_entry has miss_cookie])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct flow_action_entry has cookie])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
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
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FLOW_ACTION_ENTRY_COOKIE, 1,
			  [net/flow_offload.h struct flow_action_entry has cookie])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if flow_cls_offload has use_act_stats])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/flow_offload.h>
	],[
		struct flow_cls_offload cls;

		cls.use_act_stats = true;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_USE_ACT_STATS, 1,
			  [flow_cls_offload has use_act_stats])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if uapi/linux/nvme_ioctl.h has NVME_URING_CMD_ADMIN])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/nvme_ioctl.h>
		#include <asm-generic/ioctl.h>
	],[
		int x = NVME_URING_CMD_ADMIN;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_UAPI_LINUX_NVME_NVME_URING_CMD_ADMIN, 1,
			[uapi/linux/nvme_ioctl.h has NVME_URING_CMD_ADMIN])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blk-mq.h has blk_mq_quiesce_tagset])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		blk_mq_quiesce_tagset(NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MQ_QUEIESCE_TAGSET, 1,
			  [blk_mq_quiesce_tagset is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blk-mq.h has blk_rq_map_user_io])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		blk_rq_map_user_io(NULL, NULL, NULL, 0, 0, 0, 0, 0, 0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_RQ_MAP_USER_IO, 1,
			  [blk_rq_map_user_iv is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blkdev.h has bdev_start_io_acct])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		bdev_start_io_acct(NULL, 0, 0, 0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BDEV_START_IO_ACCT, 1,
			  [bdev_start_io_acct is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blkdev.h has bdev_start_io_acct])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		bdev_start_io_acct(NULL, 0, 0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BDEV_START_IO_ACCT_3_PARAM, 1,
			  [bdev_start_io_acct is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/fs.h struct file_operations has uring_cmd_iopoll])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/fs.h>
	],[
		struct file_operations xx = {
			.uring_cmd_iopoll = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_FILE_OPERATIONS_URING_CMD_IOPOLL, 1,
			[uring_cmd_iopoll is defined in file_operations])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/pr.h has enum pr_status])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/fs.h>
		#include <linux/pr.h>
	],[
		enum pr_status x;
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PR_STATUS, 1,
			[enum pr_status is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/bvec.h has bvec_set_virt])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/bvec.h>
	],[
		bvec_set_virt(NULL, NULL, 0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BVEC_SET_VIRT, 1,
			  [bvec_set_virt is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/dma-mapping.h has dma_opt_mapping_size])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/dma-mapping.h>
	],[
		dma_opt_mapping_size(NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DMA_OPT_MAPPING_SIZE, 1,
			  [dma_opt_mapping_size is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blk-mq.h has blk_mq_rq_state])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		blk_mq_rq_state(NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MQ_RQ_STATE, 1,
			  [blk_mq_rq_state is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/uio.h has ITER_DEST])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/uio.h>
	],[
		int x = ITER_DEST;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_ITER_DEST, 1,
				[ITER_DEST is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/bvec.h has bvec_set_page])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/bvec.h>
	],[
		bvec_set_page(NULL, NULL, 0, 0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BVEC_SET_PAGE, 1,
			[linux/bvec.h has bvec_set_page])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blkdev.h has bdev_discard_granularity])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		bdev_discard_granularity(NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BDEV_DISCARD_GRANULARITY, 1,
			[linux/blkdev.h has bdev_discard_granularity])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if kstrtox.h exist])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/kstrtox.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_KSTRTOX_H, 1,
			  [kstrtox.h exist])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blkdev.h has bdev_write_cache])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		bdev_write_cache(NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BDEV_WRITE_CACHE, 1,
			[linux/blkdev.h has bdev_write_cache])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if trace/events/sock.h has trace_sk_data_ready])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <trace/events/sock.h>
	],[
		trace_sk_data_ready(NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TRACE_EVENTS_TRACE_SK_DATA_READY, 1,
			  [trace/events/sock.h has trace_sk_data_ready])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/atomic/atomic-instrumented.h has try_cmpxchg])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/mm_types.h>
		#include <linux/atomic/atomic-instrumented.h>
	],[
			u32 x = 0;
			try_cmpxchg(&x, &x, x);
			return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_TRY_CMPXCHG, 1,
			[linux/atomic/atomic-instrumented.h has try_cmpxchg])
	],[
			AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blkdev.h has bdev_zone_no])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
			bdev_zone_no(NULL, 0);
			return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_ZONE_NO, 1,
			[linux/blkdev.h has bdev_zone_no])
	],[
			AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blkdev.h has bdev_start_io_acct])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		bdev_start_io_acct(NULL, 0, 0, 0);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BIO_START_IO_ACCT, 1,
			  [bdev_start_io_acct is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blkdev.h has bdev_is_partition])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		bdev_is_partition(NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BDEV_IS_PARTITION, 1,
			[bdev_is_partition is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct gendisk has open_mode])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		struct gendisk disk;

		disk.open_mode = BLK_OPEN_READ;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_GENDISK_OPEN_MODE, 1,
			[struct gendisk has open_mode])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if BLK_STS_RESV_CONFLICT is defined in blk_types])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk_types.h>
	],[
		blk_status_t error = BLK_STS_RESV_CONFLICT;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_STS_RESV_CONFLICT, 1,
				[blk_types.h has BLK_STS_RESV_CONFLICT])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blkdev.h has blkdev_put with holder param])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		blkdev_put(NULL, NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLKDEV_PUT_HOLDER, 1,
			[blkdev_put has holder param])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct proto_ops has sendpage])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/net.h>
	],[
		struct proto_ops x = {
			.sendpage = NULL,
		};
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PROTO_OPS_SENDPAGE, 1,
			  [net.h struct proto_ops has sendpage])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blk-mq.h blk_mq_tag_set has member nr_maps])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		struct blk_mq_tag_set x = {
			.nr_maps = 0,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MQ_TAG_SET_HAS_NR_MAP, 1,
			  [blk_mq_tag_set has member nr_maps])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blk-mq.h has enum hctx_type])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		enum hctx_type type = HCTX_TYPE_DEFAULT;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MQ_HCTX_TYPE, 1,
			[blk-mq.h has enum hctx_type])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct irq_affinity has priv])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/interrupt.h>
	],[
		struct irq_affinity affd = {
			.priv = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IRQ_AFFINITY_PRIV, 1,
			  [struct irq_affinity has priv])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/aer.h has pci_enable_pcie_error_reporting])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/aer.h>
	],[
		pci_enable_pcie_error_reporting(NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCI_ENABLE_PCIE_ERROR_REPORTING, 1,
			[linux/aer.h has pci_enable_pcie_error_reporting])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blk-mq.h blk_mq_tag_set has member map])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		struct blk_mq_tag_set x = {
			.map = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MQ_TAG_SET_HAS_MAP, 1,
			  [blk_mq_tag_set has member map])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blkdev.h has QUEUE_FLAG_PCI_P2PDMA])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		int x = QUEUE_FLAG_PCI_P2PDMA;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_QUEUE_FLAG_PCI_P2PDMA, 1,
			[QUEUE_FLAG_PCI_P2PDMA is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blkdev.h struct request has deadline])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
		#include <linux/blk-mq.h>
	],[
		struct request rq = { .deadline = 0 };
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_REQUEST_HAS_DEADLINE, 1,
			[blkdev.h struct request has deadline])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct blk_mq_ops has commit_rqs])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		struct blk_mq_ops ops = {
			.commit_rqs = NULL,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MQ_OPS_COMMIT_RQS, 1,
			  [struct blk_mq_ops has commit_rqs])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/overflow.h has struct_size_t])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/overflow.h>
	],[
		struct test {
			int arr[0];
		};

		size_t x = struct_size_t(struct test, arr, 1);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_STRUCT_SIZE_T, 1,
			  [linux/overflow.h has struct_size_t])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/pr.h has struct pr_keys])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/fs.h>
		#include <linux/pr.h>
	],[
		struct pr_keys x;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PR_KEYS, 1,
			  [linux/pr.h has struct pr_keys])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/dma-mapping.h has dma_max_mapping_size])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/dma-mapping.h>
	],[
		dma_max_mapping_size(NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DMA_MAX_MAPPING_SIZE, 1,
			  [linux/dma-mapping.h has dma_max_mapping_size])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if scsi/scsi_transport_fc.h has FC_PORT_ROLE_NVME_TARGET])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <scsi/scsi_transport_fc.h>
	],[
		int x = FC_PORT_ROLE_NVME_TARGET;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SCSI_TRANSPORT_FC_FC_PORT_ROLE_NVME_TARGET, 1,
			[scsi/scsi_transport_fc.h has FC_PORT_ROLE_NVME_TARGET])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/io_uring/cmd.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/io_uring/cmd.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IO_URING_CMD_H, 1,
				[linux/io_uring/cmd.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if hwmon_chip_info get const nvme_hwmon_ops])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/hwmon.h>
	],[
		static const struct hwmon_channel_info *const nvme_hwmon_info[] = { 0 };
		static const struct hwmon_chip_info nvme_hwmon_chip_info = {
			.info	= nvme_hwmon_info,
		};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_HWMON_CHIP_INFO_CONST_INFO, 1,
			  [hwmon_chip_info get const nvme_hwmon_ops])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if nvme_auth_transform_key returns struct nvme_dhchap_key *])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/nvme-auth.h>
	],[
		struct nvme_dhchap_key *x = nvme_auth_transform_key(NULL, NULL);
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_NVME_AUTH_TRANSFORM_KEY_DHCHAP, 1,
				[nvme_auth_transform_key returns struct nvme_dhchap_key *])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if bio.h has bio_integrity_map_user])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/bio.h>
	],[
		bio_integrity_map_user(NULL, NULL, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BIO_INTEGRITY_MAP_USER_BIO_H, 1,
			  [bio.h has bio_integrity_map_user])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if pci.h has pcie_capability_clear_and_set_word_locked])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/pci.h>
	],[
		pcie_capability_clear_and_set_word_locked(NULL, 0, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PCIE_CAPABILITY_CLEAR_AND_SET_WORD_LOCKED, 1,
			  [pci.h has pcie_capability_clear_and_set_word_locked])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blk_types.h has PAGE_SECTORS_SHIFT])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk_types.h>
	],[
		int x = PAGE_SECTORS_SHIFT;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_TYPES_PAGE_SECTORS_SHIFT, 1,
			  [PAGE_SECTORS_SHIFT is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blkdev.h has bdev_release])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		bdev_release(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BDEV_RELEASE, 1,
			[bdev_release has holder param])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/compat.h has in_compat_syscall])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/compat.h>
	],[
		in_compat_syscall();

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_IN_COMPAT_SYSCALL, 1,
			[linux/compat.h has in_compat_syscall])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/compat.h has compat_uptr_t])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/compat.h>
	],[
		compat_uptr_t x;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_COMPAT_UPTR_T, 1,
				[linux/compat.h has compat_uptr_t])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blk_alloc_queue_node has 3 args])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		blk_alloc_queue_node(0, 0, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_ALLOC_QUEUE_NODE_3_ARGS, 1,
				[blk_alloc_queue_node has 3 args])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blkdev.h struct request has mq_hctx])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
		#include <linux/blk-mq.h>
	],[
		struct request rq = { .mq_hctx = NULL };
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_REQUEST_MQ_HCTX, 1,
			[blkdev.h struct request has mq_hctx])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blk-mq.h has struct blk_mq_queue_map])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		struct blk_mq_queue_map x = {};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MQ_QUEUE_MAP, 1,
			  [linux/blk-mq.h has struct blk_mq_queue_map])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blk-mq.h has struct blk_holder_ops])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		struct blk_holder_ops x = {};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_HOLDER_OPS, 1,
			[linux/blk-mq.h has struct blk_holder_ops])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct sock has sk_use_task_frag])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <net/sock.h>
	],[
		struct sock sk = { .sk_use_task_frag = false };
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_SK_USE_TASK_FRAG, 1,
			  [struct sock has sk_use_task_frag])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if genhd.h has blk_alloc_disk with 2 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
                #include <linux/blkdev.h>
	],[
		blk_alloc_disk(NULL, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_ALLOC_DISK_2_PARAMS, 1,
				[genhd.h has blk_alloc_disk])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blkdev.h has queue_limits_commit_update])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
                #include <linux/blkdev.h>
	],[
		queue_limits_commit_update(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_QUEUE_LIMITS_COMMIT_UPDATE, 1,
				[blkdev.h has queue_limits_commit_update])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct blk_integrity has pi_offset])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		struct blk_integrity s = { .pi_offset = 42 };
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_INTEGRITY_PI_OFFSET, 1,
			  [struct blk_integrity has pi_offset])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blk-mq.h has blk_mq_alloc_disk 3 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		blk_mq_alloc_disk(NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MQ_ALLOC_DISK_3_PARAMS, 1,
			  [blk_mq_alloc_disk has 3 param])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blk-mq.h has blk_mq_alloc_queue])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
	],[
		blk_mq_alloc_queue(NULL, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_MQ_ALLOC_QUEUE, 1,
			  [blk_mq_alloc_queue is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blkdev.h has bdev_file_open_by_path])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		bdev_file_open_by_path(NULL, 0, NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BDEV_FILE_OPEN_BY_PATH, 1,
			  [linux/blkdev.h has bdev_file_open_by_path])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/gfp.h has page_frag_cache_drain])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/gfp.h>
	],[
		page_frag_cache_drain(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_PAGE_FRAG_CACHE_DRAIN, 1,
			  [linux/gfp.h has page_frag_cache_drain])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blkdev.h has blkdev_zone_mgmt with 5 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		int ret = blkdev_zone_mgmt(NULL, 0, 0, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLKDEV_ZONE_MGMT_5_PARAMS, 1,
			  [linux/blkdev.h has blkdev_zone_mgmt with 5 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/ratelimit_types.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/ratelimit_types.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_RATELIMIT_TYPES_H, 1,
			  [linux/ratelimit_types.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blkdev.h has blk_op_str])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		const char *s = blk_op_str(0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_OP_STR, 1,
			  [linux/blkdev.h has blk_op_str])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if linux/blkdev.h struct request_queue has member disk])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		struct request_queue q = { .disk = NULL};

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_REQUEST_QUEUE_DISK, 1,
			  [if linux/blkdev.h struct request_queue has member disk])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blkdev.h has QUEUE_FLAG_DISCARD])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		int x = QUEUE_FLAG_DISCARD;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_QUEUE_FLAG_DISCARD, 1,
			[QUEUE_FLAG_DISCARD is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if struct devlink_port_ops has max_io_eqs])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
	#include <net/devlink.h>
	],[
		struct devlink_port_ops ops;

		ops.port_fn_max_io_eqs_get = NULL;
		ops.port_fn_max_io_eqs_set = NULL;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_DEVLINK_PORT_MAX_IO_EQS, 1,
			[struct devlink_port_ops has max_io_eqs])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blk-mq.h or blkdev.h has RQF_MQ_INFLIGHT])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-mq.h>
		#include <linux/blkdev.h>
	],[
		int x = RQF_MQ_INFLIGHT;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_RQF_MQ_INFLIGHT, 1,
			[RQF_MQ_INFLIGHT is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blkdev.h has BLK_INTEGRITY_CSUM_CRC64])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blkdev.h>
	],[
		enum blk_integrity_checksum bic = BLK_INTEGRITY_CSUM_CRC64;

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_INTEGRITY_CSUM_CRC64, 1,
			[BLK_INTEGRITY_CSUM_CRC64 is defined])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if include/linux/blk-integrity.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-integrity.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_INTEGRITY_H, 1,
			[include/linux/blk-integrity.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if has blk_rq_integrity_map_user])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-integrity.h>
	],[
		int ret = blk_rq_integrity_map_user(NULL, NULL, 0, 0);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_RQ_INTEGRITY_MAP_USER, 1,
			[blk_rq_integrity_map_user exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if blk_rq_map_integrity_sg get 2 params])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-integrity.h>
	],[
		int ret = blk_rq_map_integrity_sg(NULL, NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BLK_RQ_MAP_INTEGRITY_SG_GET_2_PARAMS, 1,
			[blk_rq_map_integrity_sg get 2 params])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if include/linux/bio-integrity.h exists])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/bio-integrity.h>
	],[
		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_BIO_INTEGRITY_H, 1,
			[include/linux/bio-integrity.h exists])
	],[
		AC_MSG_RESULT(no)
	])

	AC_MSG_CHECKING([if rq_integrity_vec returns struct bio_vec])
	MLNX_BG_LB_LINUX_TRY_COMPILE([
		#include <linux/blk-integrity.h>
	],[
		struct bio_vec bvec = rq_integrity_vec(NULL);

		return 0;
	],[
		AC_MSG_RESULT(yes)
		MLNX_AC_DEFINE(HAVE_RQ_INTEGRITY_RETURN_BIO_VEC, 1,
			[rq_integrity_vec returns struct bio_vec])
	],[
		AC_MSG_RESULT(no)
	])
])
#
# COMPAT_CONFIG_HEADERS
#
# add -include config.h
#
AC_DEFUN([COMPAT_CONFIG_HEADERS],[
#
#	Wait for remaining build tests running in background
#
	wait
#
#	Append confdefs.h files from CONFDEFS_H_DIR to the main confdefs.h file
#
	/bin/cat CONFDEFS_H_DIR/confdefs.h.* >> confdefs.h
	/bin/rm -rf CONFDEFS_H_DIR
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
LB_LINUX_SYMVERFILE
LB_LINUX_CONFIG([MODULES],[],[
    AC_MSG_ERROR([module support is required to build mlnx kernel modules.])
])
LB_LINUX_CONFIG([MODVERSIONS])
LB_LINUX_CONFIG([KALLSYMS],[],[
    AC_MSG_ERROR([compat_mlnx requires that CONFIG_KALLSYMS is enabled in your kernel.])
])

LINUX_CONFIG_COMPAT
COMPAT_CONFIG_HEADERS

])

