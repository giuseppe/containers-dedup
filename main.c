/* rolling-dedup

   Copyright (C) 2018 Giuseppe Scrivano <giuseppe@scrivano.org>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <config.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <error.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fts.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#include <bitrotate.h>
#include <bupsplit.h>
#include <hash.h>

struct chunk
{
  char *path;
  uint64_t checksum;
  size_t offset;
  size_t len;
  ino_t ino;
  struct chunk *next;
};

static uint64_t
compute_checksum (const char *data, size_t len)
{
  size_t i;
  uint64_t ret = 0;

  for (i = 0; i < len; i++)
    ret = ~rotl64 (ret, 7) + data[i];

  return ret;
}

static struct chunk *
make_chunk (const char *data, const char *path, ino_t ino, size_t offset, size_t len)
{
  struct chunk *c = malloc (sizeof (*c));
  if (c == NULL)
    abort ();
  c->path = strdup (path);
  if (c->path == NULL)
    abort ();
  c->offset = offset;
  c->len = len;
  c->next = NULL;
  c->ino = ino;
  c->checksum = compute_checksum (data + offset, len);
  return c;
}

static size_t
chunk_hasher (const void *p, size_t s)
{
  struct chunk *c = (struct chunk *) p;
  return c->checksum % s;
}

static bool
chunk_compare (const void *n1, const void *n2)
{
  struct chunk *chunk1 = (struct chunk *) n1;
  struct chunk *chunk2 = (struct chunk *) n2;

  return chunk1->checksum == chunk2->checksum;
}

static void
chunk_free (void *p)
{
  struct chunk *c = (struct chunk *) p;
  struct chunk *next;
  free (c->path);
  next = c->next;
  free (c);
  if (next)
    chunk_free (next);
}

static int
dedup (int src_fd, int dest_fd, off_t src_off, off_t dest_off, off_t len, off_t *dedup_bytes)
{
  char b[sizeof (struct file_dedupe_range) + sizeof (struct file_dedupe_range_info)];
  struct file_dedupe_range *fdr = (struct file_dedupe_range *) &b;
  memset (b, 0, sizeof (b));

  fdr->dest_count = 1;
  fdr->src_length = len;
  fdr->src_offset = src_off;
  fdr->info[0].dest_fd = dest_fd;
  fdr->info[0].dest_offset = dest_off;

  if (ioctl (src_fd, FIDEDUPERANGE, fdr) < 0)
    return -1;

  if (fdr->info[0].status < 0)
    {
      errno = -fdr->info[0].status;
      return -1;
    }

  *dedup_bytes += fdr->info[0].bytes_deduped;

  return 0;
}

static int
dedup_list (struct chunk *l, off_t *dedup_bytes)
{
  int src_fd;
  struct chunk *dest;
  int ret = 1;

  if (l->next == NULL)
    return ret;

  src_fd = open (l->path, O_RDONLY);
  if (src_fd < 0)
    {
      for (dest = l->next; dest; dest = dest->next, ret++);
      error (0, errno, "cannot open %s", l->path);
      return ret;
    }

  for (dest = l->next; dest; dest = dest->next, ret++)
    {
      int dest_fd;

      if (dest->len != l->len)
        continue;

      if (dest->ino == l->ino)
        continue;

      dest_fd = open (dest->path, O_RDONLY);
      if (dest_fd < 0)
        continue;

      if (dedup (src_fd, dest_fd, l->offset, dest->offset, l->len, dedup_bytes) < 0)
        error (0, errno, "error deduplicating %s", dest->path);

      close (dest_fd);
    }

  close (src_fd);
  return ret;
}

static int
analyze (Hash_table *data, bool use_rolling_checksum, const char *acc_path, const char *path, struct stat *st, int *total_chunks)
{
  int fd = open (acc_path, O_RDONLY);
  void *addr;
  size_t len, off = 0;
  int ret = 0;
  size_t chunks = 0;
  size_t block_size;

  if (fd < 0)
    return fd;

  printf ("processing: %s\n", path);

  len = st->st_size;
  block_size = st->st_blksize;

  if (st->st_size < block_size)
    {
      close (fd);
      return 0;
    }

  addr = mmap (NULL, len, PROT_READ, MAP_SHARED|MAP_POPULATE, fd, 0);
  if (addr == MAP_FAILED)
    {
      close (fd);
      return -1;
    }

  while (off < len)
    {
      struct chunk *c;
      struct chunk *old = NULL;
      int next_offset;
      int aligned_off, aligned_len;

      if (! use_rolling_checksum)
        next_offset = block_size;
      else
        {
          next_offset = bupsplit_find_ofs (addr + off, len - off, NULL);
          if (next_offset == 0)
            break;
        }

      if (off & (block_size - 1) == 0)
        aligned_off = off;
      else
        aligned_off = off + block_size - (off & (block_size - 1));
      aligned_len = next_offset - (next_offset & (block_size - 1));

      if (aligned_len == 0)
        {
          off += next_offset;
          continue;
        }
      if (aligned_off + aligned_len >= len)
        break;

      c = make_chunk (addr, path, st->st_ino, aligned_off, aligned_len);
      if (c == NULL)
        break;

      ret = hash_insert_if_absent (data, c, (const void **) &old);
      if (ret < 0)
        goto exit;

      if (ret == 0)
        {
          c->next = old->next;
          old->next = c;
        }

      chunks++;
      off += next_offset;
      ret = 0;
    }

  *total_chunks += chunks;

 exit:
  munmap (addr, len);
  close (fd);

  return ret;
}

int
show_usage (bool err)
{
  FILE *o = err ? stderr : stdout;
  fprintf (o, "dedup [-hn] PATH...\n");
  fprintf (o, "  -h   show usage and exit\n");
  fprintf (o, "  -r   use rolling checksum (not recommended)\n");
  exit (err ? EXIT_FAILURE : EXIT_SUCCESS);
}

int
main (int argc, char **argv)
{
  int i;
  Hash_table *data;
  struct chunk *it;
  off_t dedup_bytes = 0;
  off_t total_bytes = 0;
  int flags, opt;
  int chunks_so_far = 0;
  int total_chunks = 0;
  bool use_rolling_checksum = false;

  data = hash_initialize (10, NULL, chunk_hasher, chunk_compare, chunk_free);

  if (argc == 1)
    return show_usage (false);

  while ((opt = getopt (argc, argv, "hr")) != -1)
    {
      switch (opt)
        {
        case 'r':
          use_rolling_checksum = true;
          break;

        case 'h':
          return show_usage (false);

        case '?':
          show_usage (true);
          break;
        }
    }

  for (i = optind; i < argc; i++)
    {
      FTS *f = fts_open (&argv[i], FTS_PHYSICAL|FTS_XDEV, NULL);

      for (;;)
        {
          FTSENT *e = fts_read (f);
          if (e == NULL)
            {
              if (errno != 0)
                error (EXIT_FAILURE, errno, "error traversing directory");
              break;
            }

          if (e->fts_info == FTS_F)
            {
              total_bytes += e->fts_statp->st_size;

              if (analyze (data, use_rolling_checksum, e->fts_accpath, e->fts_path, e->fts_statp, &total_chunks) < 0)
                error (0, errno, "error processing file %s", e->fts_path);
            }
        }

      fts_close (f);
    }

  printf ("using %zu chunks\n", total_chunks);

  for (it = hash_get_first (data); it; it = hash_get_next (data, it))
    {
      int ret;

      chunks_so_far += dedup_list (it, &dedup_bytes);

      if ((chunks_so_far % (1 + total_chunks/100)) == 0)
        printf ("deduplicating... (%.2f%%)\n", (chunks_so_far*100.0f)/total_chunks);
    }
  printf ("\n");

  if (total_bytes == 0)
    printf ("nothing done\n");
  else
    printf ("deduplicated %llu/%llu bytes (%.2f%%)\n", dedup_bytes, total_bytes, (dedup_bytes*100.0f)/total_bytes);

  return 0;
}
