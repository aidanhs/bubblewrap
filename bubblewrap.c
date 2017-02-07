/* bubblewrap
 * Copyright (C) 2016 Alexander Larsson
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "config.h"

#include <poll.h>
#include <sched.h>
#include <pwd.h>
#include <grp.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/eventfd.h>
#include <sys/fsuid.h>
#include <sys/signalfd.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <linux/sched.h>
#include <linux/filter.h>

#include "utils.h"
#include "bind-mount.h"

/* Globals to avoid having to use getuid(), since the uid/gid changes during runtime */
static uid_t real_uid;
static gid_t real_gid;
static const char *argv0;
static const char *host_tty_dev;
static int proc_fd = -1;

char *opt_chdir_path = NULL;
bool opt_needs_devpts = FALSE;

typedef enum {
  SETUP_BIND_MOUNT,
  SETUP_RO_BIND_MOUNT,
  SETUP_DEV_BIND_MOUNT,
  SETUP_MOUNT_PROC,
  SETUP_MOUNT_DEV,
  SETUP_MOUNT_TMPFS,
  SETUP_MOUNT_MQUEUE,
  SETUP_REMOUNT_RO_NO_RECURSIVE,
} SetupOpType;

typedef struct _SetupOp SetupOp;

struct _SetupOp
{
  SetupOpType type;
  const char *source;
  const char *dest;
  int         fd;
  SetupOp    *next;
};

typedef struct _LockFile LockFile;

struct _LockFile
{
  const char *path;
  LockFile   *next;
};

static SetupOp *ops = NULL;
static SetupOp *last_op = NULL;

typedef struct
{
  uint32_t op;
  uint32_t flags;
  uint32_t arg1_offset;
  uint32_t arg2_offset;
} PrivSepOp;

static SetupOp *
setup_op_new (SetupOpType type)
{
  SetupOp *op = xcalloc (sizeof (SetupOp));

  op->type = type;
  op->fd = -1;
  if (last_op != NULL)
    last_op->next = op;
  else
    ops = op;

  last_op = op;
  return op;
}


static void
usage (int ecode, FILE *out)
{
  fprintf (out, "usage: %s [OPTIONS...] COMMAND [ARGS...]\n\n", argv0);

  fprintf (out,
           "    --help                       Print this help\n"
           "    --version                    Print version\n"
           "    --chdir DIR                  Change directory to DIR\n"
           "    --bind SRC DEST              Bind mount the host path SRC on DEST\n"
           "    --dev-bind SRC DEST          Bind mount the host path SRC on DEST, allowing device access\n"
           "    --ro-bind SRC DEST           Bind mount the host path SRC readonly on DEST\n"
           "    --remount-ro DEST            Remount DEST as readonly, it doesn't recursively remount\n"
           "    --proc DEST                  Mount procfs on DEST\n"
           "    --dev DEST                   Mount new dev on DEST\n"
           "    --tmpfs DEST                 Mount new tmpfs on DEST\n"
           "    --mqueue DEST                Mount new mqueue on DEST\n"
          );
  exit (ecode);
}

static void
block_sigchild (void)
{
  sigset_t mask;
  int status;

  sigemptyset (&mask);
  sigaddset (&mask, SIGCHLD);

  if (sigprocmask (SIG_BLOCK, &mask, NULL) == -1)
    die_with_error ("sigprocmask");

  /* Reap any outstanding zombies that we may have inherited */
  while (waitpid (-1, &status, WNOHANG) > 0)
    ;
}

static void
unblock_sigchild (void)
{
  sigset_t mask;

  sigemptyset (&mask);
  sigaddset (&mask, SIGCHLD);

  if (sigprocmask (SIG_UNBLOCK, &mask, NULL) == -1)
    die_with_error ("sigprocmask");
}

/* Closes all fd:s except 0,1,2 and the passed in array of extra fds */
static int
close_extra_fds (void *data, int fd)
{
  int *extra_fds = (int *) data;
  int i;

  for (i = 0; extra_fds[i] != -1; i++)
    if (fd == extra_fds[i])
      return 0;

  if (fd <= 2)
    return 0;

  close (fd);
  return 0;
}

static int
propagate_exit_status (int status)
{
  if (WIFEXITED (status))
    return WEXITSTATUS (status);

  /* The process died of a signal, we can't really report that, but we
   * can at least be bash-compatible. The bash manpage says:
   *   The return value of a simple command is its
   *   exit status, or 128+n if the command is
   *   terminated by signal n.
   */
  if (WIFSIGNALED (status))
    return 128 + WTERMSIG (status);

  /* Weird? */
  return 255;
}

/* This stays around for as long as the initial process in the app does
 * and when that exits it exits, propagating the exit status. We do this
 * by having pid 1 in the sandbox detect this exit and tell the monitor
 * the exit status via a eventfd. We also track the exit of the sandbox
 * pid 1 via a signalfd for SIGCHLD, and exit with an error in this case.
 * This is to catch e.g. problems during setup. */
static void
monitor_child (int event_fd, pid_t child_pid)
{
  int res;
  uint64_t val;
  ssize_t s;
  int signal_fd;
  sigset_t mask;
  struct pollfd fds[2];
  int num_fds;
  struct signalfd_siginfo fdsi;
  int dont_close[] = { event_fd, -1 };
  pid_t died_pid;
  int died_status;

  /* Close all extra fds in the monitoring process.
     Any passed in fds have been passed on to the child anyway. */
  fdwalk (proc_fd, close_extra_fds, dont_close);

  sigemptyset (&mask);
  sigaddset (&mask, SIGCHLD);

  signal_fd = signalfd (-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
  if (signal_fd == -1)
    die_with_error ("Can't create signalfd");

  num_fds = 1;
  fds[0].fd = signal_fd;
  fds[0].events = POLLIN;
  if (event_fd != -1)
    {
      fds[1].fd = event_fd;
      fds[1].events = POLLIN;
      num_fds++;
    }

  while (1)
    {
      fds[0].revents = fds[1].revents = 0;
      res = poll (fds, num_fds, -1);
      if (res == -1 && errno != EINTR)
        die_with_error ("poll");

      /* Always read from the eventfd first, if pid 2 died then pid 1 often
       * dies too, and we could race, reporting that first and we'd lose
       * the real exit status. */
      if (event_fd != -1)
        {
          s = read (event_fd, &val, 8);
          if (s == -1 && errno != EINTR && errno != EAGAIN)
            die_with_error ("read eventfd");
          else if (s == 8)
            exit ((int) val - 1);
        }

      /* We need to read the signal_fd, or it will keep polling as read,
       * however we ignore the details as we get them from waitpid
       * below anway */
      s = read (signal_fd, &fdsi, sizeof (struct signalfd_siginfo));
      if (s == -1 && errno != EINTR && errno != EAGAIN)
        die_with_error ("read signalfd");

      /* We may actually get several sigchld compressed into one
         SIGCHLD, so we have to handle all of them. */
      while ((died_pid = waitpid (-1, &died_status, WNOHANG)) > 0)
        {
          /* We may be getting sigchild from other children too. For instance if
             someone created a child process, and then exec:ed bubblewrap. Ignore them */
          if (died_pid == child_pid)
            exit (propagate_exit_status (died_status));
        }
    }
}

static char *
get_newroot_path (const char *path)
{
  while (*path == '/')
    path++;
  return strconcat ("/newroot/", path);
}

static char *
get_oldroot_path (const char *path)
{
  while (*path == '/')
    path++;
  return strconcat ("/oldroot/", path);
}

static void
setup_newroot (void)
{
  SetupOp *op;

  for (op = ops; op != NULL; op = op->next)
    {
      cleanup_free char *source = NULL;
      cleanup_free char *dest = NULL;
      int source_mode = 0;
      int i;

      if (op->source)
        {
          source = get_oldroot_path (op->source);
          source_mode = get_file_mode (source);
          if (source_mode < 0)
            die_with_error ("Can't get type of source %s", op->source);
        }

      if (op->dest)
        {
          dest = get_newroot_path (op->dest);
          if (mkdir_with_parents (dest, 0755, FALSE) != 0)
            die_with_error ("Can't mkdir parents for %s", op->dest);
        }

      switch (op->type)
        {
        case SETUP_RO_BIND_MOUNT:
        case SETUP_DEV_BIND_MOUNT:
        case SETUP_BIND_MOUNT:
          if (source_mode == S_IFDIR)
            {
              if (mkdir (dest, 0755) != 0 && errno != EEXIST)
                die_with_error ("Can't mkdir %s", op->dest);
            }
          else if (ensure_file (dest, 0666) != 0)
            die_with_error ("Can't create file at %s", op->dest);

          uint32_t flags = (op->type == SETUP_RO_BIND_MOUNT ? BIND_READONLY : 0) |
                           (op->type == SETUP_DEV_BIND_MOUNT ? BIND_DEVICES : 0);
          if (bind_mount (proc_fd, source, dest, BIND_RECURSIVE | flags) != 0)
            die_with_error ("Can't bind mount %s on %s", source, dest);
          break;

        case SETUP_REMOUNT_RO_NO_RECURSIVE:
          if (bind_mount (proc_fd, NULL, dest, BIND_READONLY) != 0)
            die_with_error ("Can't remount readonly on %s", dest);
          break;

        case SETUP_MOUNT_PROC:
          if (mkdir (dest, 0755) != 0 && errno != EEXIST)
            die_with_error ("Can't mkdir %s", op->dest);

          if (mount ("proc", dest, "proc", MS_MGC_VAL | MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) != 0)
            die_with_error ("Can't mount proc on %s", dest);
          break;

        case SETUP_MOUNT_DEV:
          if (mkdir (dest, 0755) != 0 && errno != EEXIST)
            die_with_error ("Can't mkdir %s", op->dest);

          if (mount ("tmpfs", dest, "tmpfs", MS_MGC_VAL | MS_NOSUID | MS_NODEV, "mode=0755") != 0)
            die_with_error ("Can't mount tmpfs on %s", dest);

          static const char *const devnodes[] = { "null", "zero", "full", "random", "urandom", "tty" };
          for (i = 0; i < N_ELEMENTS (devnodes); i++)
            {
              cleanup_free char *node_dest = strconcat3 (dest, "/", devnodes[i]);
              cleanup_free char *node_src = strconcat ("/oldroot/dev/", devnodes[i]);
              if (create_file (node_dest, 0666, NULL) != 0)
                die_with_error ("Can't create file %s/%s", op->dest, devnodes[i]);
              if (bind_mount (proc_fd, node_src, node_dest, BIND_RECURSIVE | BIND_DEVICES) != 0)
                die_with_error ("Can't bind mount %s on %s", node_src, node_dest);
            }

          static const char *const stdionodes[] = { "stdin", "stdout", "stderr" };
          for (i = 0; i < N_ELEMENTS (stdionodes); i++)
            {
              cleanup_free char *target = xasprintf ("/proc/self/fd/%d", i);
              cleanup_free char *node_dest = strconcat3 (dest, "/", stdionodes[i]);
              if (symlink (target, node_dest) < 0)
                die_with_error ("Can't create symlink %s/%s", op->dest, stdionodes[i]);
            }

          {
            cleanup_free char *pts = strconcat (dest, "/pts");
            cleanup_free char *ptmx = strconcat (dest, "/ptmx");
            cleanup_free char *shm = strconcat (dest, "/shm");

            if (mkdir (shm, 0755) == -1)
              die_with_error ("Can't create %s/shm", op->dest);

            if (mkdir (pts, 0755) == -1)
              die_with_error ("Can't create %s/devpts", op->dest);
            if (mount ("devpts", pts, "devpts", MS_MGC_VAL | MS_NOSUID | MS_NOEXEC | 0,
                       "newinstance,ptmxmode=0666,mode=620") != 0)
              die_with_error ("Can't mount devpts on %s", pts);

            if (symlink ("pts/ptmx", ptmx) != 0)
              die_with_error ("Can't make symlink at %s/ptmx", op->dest);
          }

          /* If stdout is a tty, that means the sandbox can write to the
             outside-sandbox tty. In that case we also create a /dev/console
             that points to this tty device. This should not cause any more
             access than we already have, and it makes ttyname() work in the
             sandbox. */
          if (host_tty_dev != NULL && *host_tty_dev != 0)
            {
              cleanup_free char *src_tty_dev = strconcat ("/oldroot", host_tty_dev);
              cleanup_free char *dest_console = strconcat (dest, "/console");

              if (create_file (dest_console, 0666, NULL) != 0)
                die_with_error ("creating %s/console", op->dest);

              if (bind_mount (proc_fd, src_tty_dev, dest_console, BIND_RECURSIVE | BIND_DEVICES) != 0)
                die_with_error ("Can't bind mount %s on %s", src_tty_dev, dest_console);
            }

          break;

        case SETUP_MOUNT_TMPFS:
          if (mkdir (dest, 0755) != 0 && errno != EEXIST)
            die_with_error ("Can't mkdir %s", op->dest);

          if (mount ("tmpfs", dest, "tmpfs", MS_MGC_VAL | MS_NOSUID | MS_NODEV, "mode=0755") != 0)
            die_with_error ("Can't mount tmpfs on %s", dest);
          break;

        case SETUP_MOUNT_MQUEUE:
          if (mkdir (dest, 0755) != 0 && errno != EEXIST)
            die_with_error ("Can't mkdir %s", op->dest);

          if (mount ("mqueue", dest, "mqueue", 0, NULL) != 0)
            die_with_error ("Can't mount mqueue on %s", dest);
          break;

        default:
          die ("Unexpected type %d", op->type);
        }
    }
}

/* We need to resolve relative symlinks in the sandbox before we
   chroot so that absolute symlinks are handled correctly. We also
   need to do this after we've switched to the real uid so that
   e.g. paths on fuse mounts work */
static void
resolve_symlinks_in_ops (void)
{
  SetupOp *op;

  for (op = ops; op != NULL; op = op->next)
    {
      const char *old_source;

      switch (op->type)
        {
        case SETUP_RO_BIND_MOUNT:
        case SETUP_DEV_BIND_MOUNT:
        case SETUP_BIND_MOUNT:
          old_source = op->source;
          op->source = realpath (old_source, NULL);
          if (op->source == NULL)
            die_with_error ("Can't find source path %s", old_source);
          break;
        default:
          break;
        }
    }
}


static void
parse_args (int    *argcp,
            char ***argvp)
{
  SetupOp *op;
  int argc = *argcp;
  char **argv = *argvp;
  /* I can't imagine a case where someone wants more than this.
   * If you do...you should be able to pass multiple files
   * via a single tmpfs and linking them there, etc.
   *
   * We're adding this hardening due to precedent from
   * http://googleprojectzero.blogspot.com/2014/08/the-poisoned-nul-byte-2014-edition.html
   *
   * I picked 9000 because the Internet told me to and it was hard to
   * resist.
   */
  static const uint32_t MAX_ARGS = 9000;

  if (argc > MAX_ARGS)
    die ("Exceeded maximum number of arguments %u", MAX_ARGS);

  while (argc > 0)
    {
      const char *arg = argv[0];

      if (strcmp (arg, "--help") == 0)
        {
          usage (EXIT_SUCCESS, stdout);
        }
      else if (strcmp (arg, "--version") == 0)
        {
          printf ("%s\n", PACKAGE_STRING);
          exit (0);
        }
      else if (strcmp (arg, "--chdir") == 0)
        {
          if (argc < 2)
            die ("--chdir takes one argument");

          opt_chdir_path = argv[1];
          argv++;
          argc--;
        }
      else if (strcmp (arg, "--remount-ro") == 0)
        {
          SetupOp *op = setup_op_new (SETUP_REMOUNT_RO_NO_RECURSIVE);
          op->dest = argv[1];

          argv++;
          argc--;
        }
      else if (strcmp (arg, "--bind") == 0)
        {
          if (argc < 3)
            die ("--bind takes two arguments");

          op = setup_op_new (SETUP_BIND_MOUNT);
          op->source = argv[1];
          op->dest = argv[2];

          argv += 2;
          argc -= 2;
        }
      else if (strcmp (arg, "--ro-bind") == 0)
        {
          if (argc < 3)
            die ("--ro-bind takes two arguments");

          op = setup_op_new (SETUP_RO_BIND_MOUNT);
          op->source = argv[1];
          op->dest = argv[2];

          argv += 2;
          argc -= 2;
        }
      else if (strcmp (arg, "--dev-bind") == 0)
        {
          if (argc < 3)
            die ("--dev-bind takes two arguments");

          op = setup_op_new (SETUP_DEV_BIND_MOUNT);
          op->source = argv[1];
          op->dest = argv[2];

          argv += 2;
          argc -= 2;
        }
      else if (strcmp (arg, "--proc") == 0)
        {
          if (argc < 2)
            die ("--proc takes an argument");

          op = setup_op_new (SETUP_MOUNT_PROC);
          op->dest = argv[1];

          argv += 1;
          argc -= 1;
        }
      else if (strcmp (arg, "--dev") == 0)
        {
          if (argc < 2)
            die ("--dev takes an argument");

          op = setup_op_new (SETUP_MOUNT_DEV);
          op->dest = argv[1];
          opt_needs_devpts = TRUE;

          argv += 1;
          argc -= 1;
        }
      else if (strcmp (arg, "--tmpfs") == 0)
        {
          if (argc < 2)
            die ("--tmpfs takes an argument");

          op = setup_op_new (SETUP_MOUNT_TMPFS);
          op->dest = argv[1];

          argv += 1;
          argc -= 1;
        }
      else if (strcmp (arg, "--mqueue") == 0)
        {
          if (argc < 2)
            die ("--mqueue takes an argument");

          op = setup_op_new (SETUP_MOUNT_MQUEUE);
          op->dest = argv[1];

          argv += 1;
          argc -= 1;
        }
      else if (*arg == '-')
        {
          die ("Unknown option %s", arg);
        }
      else
        {
          break;
        }

      argv++;
      argc--;
    }

  *argcp = argc;
  *argvp = argv;
}

int
main (int    argc,
      char **argv)
{
  mode_t old_umask;
  cleanup_free char *base_path = NULL;
  int clone_flags;
  char *old_cwd = NULL;
  pid_t pid;
  int event_fd = -1;
  int child_wait_fd = -1;
  const char *new_cwd;
  uint64_t val;
  int res UNUSED;

  real_uid = getuid ();
  real_gid = getgid ();

  /* Never gain any more privs during exec */
  if (prctl (PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
    die_with_error ("prctl(PR_SET_NO_NEW_CAPS) failed");

  /* The initial code is run with high permissions
     (i.e. CAP_SYS_ADMIN), so take lots of care. */

  argv0 = argv[0];

  if (isatty (1))
    host_tty_dev = ttyname (1);

  argv++;
  argc--;

  if (argc == 0)
    usage (EXIT_FAILURE, stderr);

  parse_args (&argc, &argv);

  if (!(getuid() == 0 && getgid() == 0 && geteuid() == 0 && getgid() == 0)) {
    die("must run machroot as root");
  }

  if (argc == 0)
    usage (EXIT_FAILURE, stderr);

  __debug__ (("Creating root mount point\n"));

  /* We need to read stuff from proc during the pivot_root dance, etc.
     Lets keep a fd to it open */
  proc_fd = open ("/proc", O_RDONLY | O_PATH);
  if (proc_fd == -1)
    die_with_error ("Can't open /proc");

  /* We need *some* mountpoint where we can mount the root tmpfs.
     We first try in /run, and if that fails, try in /tmp. */
  base_path = xasprintf ("/run/user/%d/.bubblewrap", real_uid);
  if (mkdir (base_path, 0755) && errno != EEXIST)
    {
      free (base_path);
      base_path = xasprintf ("/tmp/.bubblewrap-%d", real_uid);
      if (mkdir (base_path, 0755) && errno != EEXIST)
        die_with_error ("Creating root mountpoint failed");
    }

  __debug__ (("creating new namespace\n"));

  /* We block sigchild here so that we can use signalfd in the monitor. */
  block_sigchild ();

  clone_flags = SIGCHLD | CLONE_NEWNS;

  child_wait_fd = eventfd (0, EFD_CLOEXEC);
  if (child_wait_fd == -1)
    die_with_error ("eventfd()");

  pid = raw_clone (clone_flags, NULL);
  if (pid == -1)
    {
      die_with_error ("Creating new namespace failed");
    }

  if (pid != 0)
    {
      /* Parent, outside sandbox, privileged (initially) */

      /* Initial launched process, wait for exec:ed command to exit */

      /* Let child run now that the uid maps are set up */
      val = 1;
      res = write (child_wait_fd, &val, 8);
      /* Ignore res, if e.g. the child died and closed child_wait_fd we don't want to error out here */
      close (child_wait_fd);

      monitor_child (event_fd, pid);
      exit (0); /* Should not be reached, but better safe... */
    }

  /* Wait for the parent to init uid/gid maps and drop caps */
  res = read (child_wait_fd, &val, 8);
  close (child_wait_fd);

  old_umask = umask (0);

  /* Need to do this before the chroot, but after we're the real uid */
  resolve_symlinks_in_ops ();

  /* Mark everything as slave, so that we still
   * receive mounts from the real root, but don't
   * propagate mounts to the real root. */
  if (mount (NULL, "/", NULL, MS_SLAVE | MS_REC, NULL) < 0)
    die_with_error ("Failed to make / slave");

  /* Create a tmpfs which we will use as / in the namespace */
  if (mount ("", base_path, "tmpfs", MS_NODEV | MS_NOSUID, NULL) != 0)
    die_with_error ("Failed to mount tmpfs");

  old_cwd = get_current_dir_name ();

  /* Chdir to the new root tmpfs mount. This will be the CWD during
     the entire setup. Access old or new root via "oldroot" and "newroot". */
  if (chdir (base_path) != 0)
    die_with_error ("chdir base_path");

  /* We create a subdir "$base_path/newroot" for the new root, that
   * way we can pivot_root to base_path, and put the old root at
   * "$base_path/oldroot". This avoids problems accessing the oldroot
   * dir if the user requested to bind mount something over / */

  if (mkdir ("newroot", 0755))
    die_with_error ("Creating newroot failed");

  if (mkdir ("oldroot", 0755))
    die_with_error ("Creating oldroot failed");

  if (pivot_root (base_path, "oldroot"))
    die_with_error ("pivot_root");

  if (chdir ("/") != 0)
    die_with_error ("chdir / (base path)");

  setup_newroot ();

  /* The old root better be rprivate or we will send unmount events to the parent namespace */
  if (mount ("oldroot", "oldroot", NULL, MS_REC | MS_PRIVATE, NULL) != 0)
    die_with_error ("Failed to make old root rprivate");

  if (umount2 ("oldroot", MNT_DETACH))
    die_with_error ("unmount old root");

  /* Now make /newroot the real root */
  if (chdir ("/newroot") != 0)
    die_with_error ("chdir newroot");
  if (chroot ("/newroot") != 0)
    die_with_error ("chroot /newroot");
  if (chdir ("/") != 0)
    die_with_error ("chdir /");

  umask (old_umask);

  new_cwd = "/";
  if (opt_chdir_path)
    {
      if (chdir (opt_chdir_path))
        die_with_error ("Can't chdir to %s", opt_chdir_path);
      new_cwd = opt_chdir_path;
    }
  else if (chdir (old_cwd) == 0)
    {
      /* If the old cwd is mapped in the sandbox, go there */
      new_cwd = old_cwd;
    }
  else
    {
      /* If the old cwd is not mapped, go to home */
      const char *home = getenv ("HOME");
      if (home != NULL &&
          chdir (home) == 0)
        new_cwd = home;
    }
  xsetenv ("PWD", new_cwd, 1);
  free (old_cwd);

  __debug__ (("launch executable %s\n", argv[0]));

  if (proc_fd != -1)
    close (proc_fd);

  /* We want sigchild in the child */
  unblock_sigchild ();

  if (execvp (argv[0], argv) == -1)
    die_with_error ("execvp %s", argv[0]);

  return 0;
}
