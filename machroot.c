/* machroot
 * Copyright (C) 2016 Alexander Larsson, Aidan Hobson Sayers
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

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <sys/capability.h> header file. */
#define HAVE_SYS_CAPABILITY_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "machroot 0.1.0"

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif


#include <poll.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/prctl.h>

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#if 0
#define __debug__(x) printf x
#else
#define __debug__(x)
#endif

#define UNUSED __attribute__((__unused__))

#define N_ELEMENTS(arr) (sizeof (arr) / sizeof ((arr)[0]))

#define TRUE 1
#define FALSE 0
typedef int bool;

static void  die_with_error (const char *format,
                      ...) __attribute__((__noreturn__)) __attribute__((format (printf, 1, 2)));
static void  die (const char *format,
           ...) __attribute__((__noreturn__)) __attribute__((format (printf, 1, 2)));
static void  die_oom (void) __attribute__((__noreturn__));

static void *xmalloc (size_t size);
static void *xcalloc (size_t size);
static void *xrealloc (void  *ptr,
                size_t size);
static char *xstrdup (const char *str);
static void  xsetenv (const char *name,
               const char *value,
               int         overwrite);
static char *strconcat (const char *s1,
                 const char *s2);
static char *strconcat3 (const char *s1,
                  const char *s2,
                  const char *s3);
static char * xasprintf (const char *format,
                  ...) __attribute__((format (printf, 1, 2)));
static bool  has_path_prefix (const char *str,
                       const char *prefix);
static bool  path_equal (const char *path1,
                  const char *path2);
static int   fdwalk (int                     proc_fd,
              int                     (*cb)(void *data,
                                  int fd),
              void                   *data);
static char *load_file_data (int     fd,
                      size_t *size);
static char *load_file_at (int         dirfd,
                    const char *path);
static int   write_to_fd (int         fd,
                   const char *content,
                   ssize_t     len);
static int   create_file (const char *path,
                   mode_t      mode,
                   const char *content);
static int   ensure_file (const char *path,
                   mode_t      mode);
static int   get_file_mode (const char *pathname);
static int   mkdir_with_parents (const char *pathname,
                          int         mode,
                          bool        create_last);

/* syscall wrappers */
static int   raw_clone (unsigned long flags,
                 void         *child_stack);
static int   pivot_root (const char *new_root,
                  const char *put_old);

static inline void
cleanup_freep (void *p)
{
  void **pp = (void **) p;

  if (*pp)
    free (*pp);
}

#define cleanup_free __attribute__((cleanup (cleanup_freep)))

static inline void *
steal_pointer (void *pp)
{
  void **ptr = (void **) pp;
  void *ref;

  ref = *ptr;
  *ptr = NULL;

  return ref;
}

/* type safety */
#define steal_pointer(pp) \
  (0 ? (*(pp)) : (steal_pointer) (pp))

static void
die_with_error (const char *format, ...)
{
  va_list args;
  int errsv;

  errsv = errno;

  va_start (args, format);
  vfprintf (stderr, format, args);
  va_end (args);

  fprintf (stderr, ": %s\n", strerror (errsv));

  exit (1);
}

static void
die (const char *format, ...)
{
  va_list args;

  va_start (args, format);
  vfprintf (stderr, format, args);
  va_end (args);

  fprintf (stderr, "\n");

  exit (1);
}

static void
die_oom (void)
{
  puts ("Out of memory");
  exit (1);
}

static void *
xmalloc (size_t size)
{
  void *res = malloc (size);

  if (res == NULL)
    die_oom ();
  return res;
}

static void *
xcalloc (size_t size)
{
  void *res = calloc (1, size);

  if (res == NULL)
    die_oom ();
  return res;
}

static void *
xrealloc (void *ptr, size_t size)
{
  void *res = realloc (ptr, size);

  if (size != 0 && res == NULL)
    die_oom ();
  return res;
}

static char *
xstrdup (const char *str)
{
  char *res;

  assert (str != NULL);

  res = strdup (str);
  if (res == NULL)
    die_oom ();

  return res;
}

/* Compares if str has a specific path prefix. This differs
   from a regular prefix in two ways. First of all there may
   be multiple slashes separating the path elements, and
   secondly, if a prefix is matched that has to be en entire
   path element. For instance /a/prefix matches /a/prefix/foo/bar,
   but not /a/prefixfoo/bar. */
static bool
has_path_prefix (const char *str,
                 const char *prefix)
{
  while (TRUE)
    {
      /* Skip consecutive slashes to reach next path
         element */
      while (*str == '/')
        str++;
      while (*prefix == '/')
        prefix++;

      /* No more prefix path elements? Done! */
      if (*prefix == 0)
        return TRUE;

      /* Compare path element */
      while (*prefix != 0 && *prefix != '/')
        {
          if (*str != *prefix)
            return FALSE;
          str++;
          prefix++;
        }

      /* Matched prefix path element,
         must be entire str path element */
      if (*str != '/' && *str != 0)
        return FALSE;
    }
}

static bool
path_equal (const char *path1,
            const char *path2)
{
  while (TRUE)
    {
      /* Skip consecutive slashes to reach next path
         element */
      while (*path1 == '/')
        path1++;
      while (*path2 == '/')
        path2++;

      /* No more prefix path elements? Done! */
      if (*path1 == 0 || *path2 == 0)
        return *path1 == 0 && *path2 == 0;

      /* Compare path element */
      while (*path1 != 0 && *path1 != '/')
        {
          if (*path1 != *path2)
            return FALSE;
          path1++;
          path2++;
        }

      /* Matched path1 path element, must be entire path element */
      if (*path2 != '/' && *path2 != 0)
        return FALSE;
    }
}


static void
xsetenv (const char *name, const char *value, int overwrite)
{
  if (setenv (name, value, overwrite))
    die ("setenv failed");
}

static char *
strconcat (const char *s1,
           const char *s2)
{
  size_t len = 0;
  char *res;

  if (s1)
    len += strlen (s1);
  if (s2)
    len += strlen (s2);

  res = xmalloc (len + 1);
  *res = 0;
  if (s1)
    strcat (res, s1);
  if (s2)
    strcat (res, s2);

  return res;
}

static char *
strconcat3 (const char *s1,
            const char *s2,
            const char *s3)
{
  size_t len = 0;
  char *res;

  if (s1)
    len += strlen (s1);
  if (s2)
    len += strlen (s2);
  if (s3)
    len += strlen (s3);

  res = xmalloc (len + 1);
  *res = 0;
  if (s1)
    strcat (res, s1);
  if (s2)
    strcat (res, s2);
  if (s3)
    strcat (res, s3);

  return res;
}

static char *
xasprintf (const char *format,
           ...)
{
  char *buffer = NULL;
  va_list args;

  va_start (args, format);
  if (vasprintf (&buffer, format, args) == -1)
    die_oom ();
  va_end (args);

  return buffer;
}

static int
fdwalk (int proc_fd, int (*cb)(void *data,
                               int   fd), void *data)
{
  int open_max;
  int fd;
  int dfd;
  int res = 0;
  DIR *d;

  dfd = openat (proc_fd, "self/fd", O_DIRECTORY | O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOCTTY);
  if (dfd == -1)
    return res;

  if ((d = fdopendir (dfd)))
    {
      struct dirent *de;

      while ((de = readdir (d)))
        {
          long l;
          char *e = NULL;

          if (de->d_name[0] == '.')
            continue;

          errno = 0;
          l = strtol (de->d_name, &e, 10);
          if (errno != 0 || !e || *e)
            continue;

          fd = (int) l;

          if ((long) fd != l)
            continue;

          if (fd == dirfd (d))
            continue;

          if ((res = cb (data, fd)) != 0)
            break;
        }

      closedir (d);
      return res;
    }

  open_max = sysconf (_SC_OPEN_MAX);

  for (fd = 0; fd < open_max; fd++)
    if ((res = cb (data, fd)) != 0)
      break;

  return res;
}

/* Sets errno on error (!= 0), ENOSPC on short write */
static int
write_to_fd (int         fd,
             const char *content,
             ssize_t     len)
{
  ssize_t res;

  while (len > 0)
    {
      res = write (fd, content, len);
      if (res < 0 && errno == EINTR)
        continue;
      if (res <= 0)
        {
          if (res == 0) /* Unexpected short write, should not happen when writing to a file */
            errno = ENOSPC;
          return -1;
        }
      len -= res;
      content += res;
    }

  return 0;
}

/* Sets errno on error (!= 0), ENOSPC on short write */
static int
create_file (const char *path,
             mode_t      mode,
             const char *content)
{
  int fd;
  int res;
  int errsv;

  fd = creat (path, mode);
  if (fd == -1)
    return -1;

  res = 0;
  if (content)
    res = write_to_fd (fd, content, strlen (content));

  errsv = errno;
  close (fd);
  errno = errsv;

  return res;
}

static int
ensure_file (const char *path,
             mode_t      mode)
{
  struct stat buf;

  /* We check this ahead of time, otherwise
     the create file will fail in the read-only
     case with EROFD instead of EEXIST */
  if (stat (path, &buf) ==  0 &&
      S_ISREG (buf.st_mode))
    return 0;

  if (create_file (path, mode, NULL) != 0 &&  errno != EEXIST)
    return -1;

  return 0;
}


/* Sets errno on error (== NULL),
 * Always ensures terminating zero */
static char *
load_file_data (int     fd,
                size_t *size)
{
  cleanup_free char *data = NULL;
  ssize_t data_read;
  ssize_t data_len;
  ssize_t res;
  int errsv;

  data_read = 0;
  data_len = 4080;
  data = xmalloc (data_len);

  do
    {
      if (data_len == data_read + 1)
        {
          data_len *= 2;
          data = xrealloc (data, data_len);
        }

      do
        res = read (fd, data + data_read, data_len - data_read - 1);
      while (res < 0 && errno == EINTR);

      if (res < 0)
        {
          errsv = errno;
          close (fd);
          errno = errsv;
          return NULL;
        }

      data_read += res;
    }
  while (res > 0);

  data[data_read] = 0;

  if (size)
    *size = (size_t) data_read;

  return steal_pointer (&data);
}

/* Sets errno on error (== NULL),
 * Always ensures terminating zero */
static char *
load_file_at (int         dirfd,
              const char *path)
{
  int fd;
  char *data;
  int errsv;

  fd = openat (dirfd, path, O_CLOEXEC | O_RDONLY);
  if (fd == -1)
    return NULL;

  data = load_file_data (fd, NULL);

  errsv = errno;
  close (fd);
  errno = errsv;

  return data;
}

/* Sets errno on error (< 0) */
static int
get_file_mode (const char *pathname)
{
  struct stat buf;

  if (stat (pathname, &buf) !=  0)
    return -1;

  return buf.st_mode & S_IFMT;
}

/* Sets errno on error (!= 0) */
static int
mkdir_with_parents (const char *pathname,
                    int         mode,
                    bool        create_last)
{
  cleanup_free char *fn = NULL;
  char *p;
  struct stat buf;

  if (pathname == NULL || *pathname == '\0')
    {
      errno = EINVAL;
      return -1;
    }

  fn = xstrdup (pathname);

  p = fn;
  while (*p == '/')
    p++;

  do
    {
      while (*p && *p != '/')
        p++;

      if (!*p)
        p = NULL;
      else
        *p = '\0';

      if (!create_last && p == NULL)
        break;

      if (stat (fn, &buf) !=  0)
        {
          if (mkdir (fn, mode) == -1 && errno != EEXIST)
            return -1;
        }
      else if (!S_ISDIR (buf.st_mode))
        {
          errno = ENOTDIR;
          return -1;
        }

      if (p)
        {
          *p++ = '/';
          while (*p && *p == '/')
            p++;
        }
    }
  while (p);

  return 0;
}

static int
raw_clone (unsigned long flags,
           void         *child_stack)
{
  return (int) syscall (__NR_clone, flags, child_stack);
}

static int
pivot_root (const char * new_root, const char * put_old)
{
  return syscall (__NR_pivot_root, new_root, put_old);
}





typedef enum {
  BIND_READONLY = (1 << 0),
  BIND_DEVICES = (1 << 2),
  BIND_RECURSIVE = (1 << 3),
} bind_option_t;

static int bind_mount (int           proc_fd,
                const char   *src,
                const char   *dest,
                bind_option_t options);

static char *
skip_token (char *line, bool eat_whitespace)
{
  while (*line != ' ' && *line != '\n')
    line++;

  if (eat_whitespace && *line == ' ')
    line++;

  return line;
}

static char *
unescape_inline (char *escaped)
{
  char *unescaped, *res;
  const char *end;

  res = escaped;
  end = escaped + strlen (escaped);

  unescaped = escaped;
  while (escaped < end)
    {
      if (*escaped == '\\')
        {
          *unescaped++ =
            ((escaped[1] - '0') << 6) |
            ((escaped[2] - '0') << 3) |
            ((escaped[3] - '0') << 0);
          escaped += 4;
        }
      else
        {
          *unescaped++ = *escaped++;
        }
    }
  *unescaped = 0;
  return res;
}

static bool
match_token (const char *token, const char *token_end, const char *str)
{
  while (token != token_end && *token == *str)
    {
      token++;
      str++;
    }
  if (token == token_end)
    return *str == 0;

  return FALSE;
}

static unsigned long
decode_mountoptions (const char *options)
{
  const char *token, *end_token;
  int i;
  unsigned long flags = 0;
  static const struct  { int   flag;
                         char *name;
  } flags_data[] = {
    { 0, "rw" },
    { MS_RDONLY, "ro" },
    { MS_NOSUID, "nosuid" },
    { MS_NODEV, "nodev" },
    { MS_NOEXEC, "noexec" },
    { MS_NOATIME, "noatime" },
    { MS_NODIRATIME, "nodiratime" },
    { MS_RELATIME, "relatime" },
    { 0, NULL }
  };

  token = options;
  do
    {
      end_token = strchr (token, ',');
      if (end_token == NULL)
        end_token = token + strlen (token);

      for (i = 0; flags_data[i].name != NULL; i++)
        {
          if (match_token (token, end_token, flags_data[i].name))
            {
              flags |= flags_data[i].flag;
              break;
            }
        }

      if (*end_token != 0)
        token = end_token + 1;
      else
        token = NULL;
    }
  while (token != NULL);

  return flags;
}

typedef struct MountInfo MountInfo;
struct MountInfo {
  char *mountpoint;
  unsigned long options;
};

typedef MountInfo *MountTab;

static void
mount_tab_free (MountTab tab)
{
  int i;

  for (i = 0; tab[i].mountpoint != NULL; i++)
    free (tab[i].mountpoint);
  free (tab);
}

static inline void
cleanup_mount_tabp (void *p)
{
  void **pp = (void **) p;

  if (*pp)
    mount_tab_free ((MountTab)*pp);
}

#define cleanup_mount_tab __attribute__((cleanup (cleanup_mount_tabp)))

typedef struct MountInfoLine MountInfoLine;
struct MountInfoLine {
  const char *mountpoint;
  const char *options;
  bool covered;
  int id;
  int parent_id;
  MountInfoLine *first_child;
  MountInfoLine *next_sibling;
};

static unsigned int
count_lines (const char *data)
{
  unsigned int count = 0;
  const char *p = data;

  while (*p != 0)
    {
      if (*p == '\n')
        count++;
      p++;
    }

  /* If missing final newline, add one */
  if (p > data && *(p-1) != '\n')
    count++;

  return count;
}

static int
count_mounts (MountInfoLine *line)
{
  MountInfoLine *child;
  int res = 0;

  if (!line->covered)
    res += 1;

  child = line->first_child;
  while (child != NULL)
    {
      res += count_mounts (child);
      child = child->next_sibling;
    }

  return res;
}

static MountInfo *
collect_mounts (MountInfo *info, MountInfoLine *line)
{
  MountInfoLine *child;

  if (!line->covered)
    {
      info->mountpoint = xstrdup (line->mountpoint);
      info->options = decode_mountoptions (line->options);
      info ++;
    }

  child = line->first_child;
  while (child != NULL)
    {
      info = collect_mounts (info, child);
      child = child->next_sibling;
    }

  return info;
}

static MountTab
parse_mountinfo (int  proc_fd,
                 const char *root_mount)
{
  cleanup_free char *mountinfo = NULL;
  cleanup_free MountInfoLine *lines = NULL;
  cleanup_free MountInfoLine **by_id = NULL;
  cleanup_mount_tab MountTab mount_tab = NULL;
  MountInfo *end_tab;
  int n_mounts;
  char *line;
  int i;
  int max_id;
  unsigned int n_lines;
  int root;

  mountinfo = load_file_at (proc_fd, "self/mountinfo");
  if (mountinfo == NULL)
    die_with_error ("Can't open /proc/self/mountinfo");

  n_lines = count_lines (mountinfo);
  lines = xcalloc (n_lines * sizeof (MountInfoLine));

  max_id = 0;
  line = mountinfo;
  i = 0;
  root = -1;
  while (*line != 0)
    {
      int rc, consumed = 0;
      unsigned int maj, min;
      char *end;
      char *rest;
      char *mountpoint;
      char *mountpoint_end;
      char *options;
      char *options_end;
      char *next_line;

      assert (i < n_lines);

      end = strchr (line, '\n');
      if (end != NULL)
        {
          *end = 0;
          next_line = end + 1;
        }
      else
        next_line = line + strlen (line);

      rc = sscanf (line, "%d %d %u:%u %n", &lines[i].id, &lines[i].parent_id, &maj, &min, &consumed);
      if (rc != 4)
        die ("Can't parse mountinfo line");
      rest = line + consumed;

      rest = skip_token (rest, TRUE); /* mountroot */
      mountpoint = rest;
      rest = skip_token (rest, FALSE); /* mountpoint */
      mountpoint_end = rest++;
      options = rest;
      rest = skip_token (rest, FALSE); /* vfs options */
      options_end = rest;

      *mountpoint_end = 0;
      lines[i].mountpoint = unescape_inline (mountpoint);

      *options_end = 0;
      lines[i].options = options;

      if (lines[i].id > max_id)
        max_id = lines[i].id;
      if (lines[i].parent_id > max_id)
        max_id = lines[i].parent_id;

      if (path_equal (lines[i].mountpoint, root_mount))
        root = i;

      i++;
      line = next_line;
    }
  assert (i == n_lines);

  if (root == -1)
    {
      mount_tab = xcalloc (sizeof (MountInfo) * (1));
      return steal_pointer (&mount_tab);
    }

  by_id = xcalloc ((max_id + 1) * sizeof (MountInfoLine*));
  for (i = 0; i < n_lines; i++)
    by_id[lines[i].id] = &lines[i];

  for (i = 0; i < n_lines; i++)
    {
      MountInfoLine *this = &lines[i];
      MountInfoLine *parent = by_id[this->parent_id];
      MountInfoLine **to_sibling;
      MountInfoLine *sibling;
      bool covered = FALSE;

      if (!has_path_prefix (this->mountpoint, root_mount))
        continue;

      if (parent == NULL)
        continue;

      if (strcmp (parent->mountpoint, this->mountpoint) == 0)
        parent->covered = TRUE;

      to_sibling = &parent->first_child;
      sibling = parent->first_child;
      while (sibling != NULL)
        {
          /* If this mountpoint is a path prefix of the sibling,
           * say this->mp=/foo/bar and sibling->mp=/foo, then it is
           * covered by the sibling, and we drop it. */
          if (has_path_prefix (this->mountpoint, sibling->mountpoint))
            {
              covered = TRUE;
              break;
            }

          /* If the sibling is a path prefix of this mount point,
           * say this->mp=/foo and sibling->mp=/foo/bar, then the sibling
           * is covered, and we drop it.
            */
          if (has_path_prefix (sibling->mountpoint, this->mountpoint))
            *to_sibling = sibling->next_sibling;
          else
            to_sibling = &sibling->next_sibling;
          sibling = sibling->next_sibling;
        }

      if (covered)
          continue;

      *to_sibling = this;
    }

  n_mounts = count_mounts (&lines[root]);
  mount_tab = xcalloc (sizeof (MountInfo) * (n_mounts + 1));

  end_tab = collect_mounts (&mount_tab[0], &lines[root]);
  assert (end_tab == &mount_tab[n_mounts]);

  return steal_pointer (&mount_tab);
}

static int
bind_mount (int           proc_fd,
            const char   *src,
            const char   *dest,
            bind_option_t options)
{
  bool readonly = (options & BIND_READONLY) != 0;
  bool devices = (options & BIND_DEVICES) != 0;
  bool recursive = (options & BIND_RECURSIVE) != 0;
  unsigned long current_flags, new_flags;
  cleanup_mount_tab MountTab mount_tab = NULL;
  cleanup_free char *resolved_dest = NULL;
  int i;

  if (src)
    {
      if (mount (src, dest, NULL, MS_MGC_VAL | MS_BIND | (recursive ? MS_REC : 0), NULL) != 0)
        return 1;
    }

  /* The mount operation will resolve any symlinks in the destination
     path, so to find it in the mount table we need to do that too. */
  resolved_dest = realpath (dest, NULL);
  if (resolved_dest == NULL)
    return 2;

  mount_tab = parse_mountinfo (proc_fd, resolved_dest);
  if (mount_tab[0].mountpoint == NULL)
    {
      errno = EINVAL;
      return 2; /* No mountpoint at dest */
    }

  assert (path_equal (mount_tab[0].mountpoint, resolved_dest));
  current_flags = mount_tab[0].options;
  new_flags = current_flags | (devices ? 0 : MS_NODEV) | MS_NOSUID | (readonly ? MS_RDONLY : 0);
  if (new_flags != current_flags &&
      mount ("none", resolved_dest,
             NULL, MS_MGC_VAL | MS_BIND | MS_REMOUNT | new_flags, NULL) != 0)
    return 3;

  /* We need to work around the fact that a bind mount does not apply the flags, so we need to manually
   * apply the flags to all submounts in the recursive case.
   * Note: This does not apply the flags to mounts which are later propagated into this namespace.
   */
  if (recursive)
    {
      for (i = 1; mount_tab[i].mountpoint != NULL; i++)
        {
          current_flags = mount_tab[i].options;
          new_flags = current_flags | (devices ? 0 : MS_NODEV) | MS_NOSUID | (readonly ? MS_RDONLY : 0);
          if (new_flags != current_flags &&
              mount ("none", mount_tab[i].mountpoint,
                     NULL, MS_MGC_VAL | MS_BIND | MS_REMOUNT | new_flags, NULL) != 0)
            {
              /* If we can't read the mountpoint we can't remount it, but that should
                 be safe to ignore because its not something the user can access. */
              if (errno != EACCES)
                return 5;
            }
        }
    }

  return 0;
}



/* Globals to avoid having to use getuid(), since the uid/gid changes during runtime */
static uid_t real_uid;
static gid_t real_gid;
static const char *argv0;
static const char *host_tty_dev;
static int proc_fd = -1;

static char *opt_chdir_path = NULL;

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
  SetupOp    *next;
};

static SetupOp *ops = NULL;
static SetupOp *last_op = NULL;

static SetupOp *
setup_op_new (SetupOpType type)
{
  SetupOp *op = xcalloc (sizeof (SetupOp));

  op->type = type;
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
             someone created a child process, and then exec:ed machroot. Ignore them */
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

int machroot (int argc, char **argv);

int
machroot (int    argc,
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
  base_path = xasprintf ("/run/user/%d/.machroot", real_uid);
  if (mkdir (base_path, 0755) && errno != EEXIST)
    {
      free (base_path);
      base_path = xasprintf ("/tmp/.machroot-%d", real_uid);
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
