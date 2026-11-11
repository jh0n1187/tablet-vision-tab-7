/* Offline EROFS to PAX exporter. Source device opened read-only. */
#include <archive.h>
#include <archive_entry.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "erofs/config.h"
#include "erofs/io.h"
#include "erofs/dir.h"
static struct erofs_sb_info sb;
static struct archive *out;
struct link { erofs_nid_t nid; char *path; struct link *next; };
static struct link *links;
struct walk { struct erofs_dir_context ctx; const char *path; unsigned depth; };
static void die(const char *what) { fprintf(stderr,"export: %s\n",what); exit(1); }
static void check(int n, const char *s) { if(n<0) die(s); }
static void emit(erofs_nid_t nid, const char *path, unsigned depth);
static int child(struct erofs_dir_context *ctx) {
 struct walk *w=(void *)ctx;
 if(ctx->dot_dotdot) return 0;
 char *p; if(asprintf(&p,"%s/%.*s",w->path,ctx->de_namelen,ctx->dname)<0) die("path allocation");
 emit(ctx->de_nid,p,w->depth+1); free(p); return 0;
}
static void emit(erofs_nid_t nid, const char *path, unsigned depth) {
 if(depth>128) die("directory depth limit");
 struct erofs_inode in={.sbi=&sb,.nid=nid};
 check(erofs_read_inode_from_disk(&in),"read inode");
 struct archive_entry *e=archive_entry_new(); if(!e) die("entry allocation");
 archive_entry_set_pathname(e,path); archive_entry_set_mode(e,in.i_mode);
 archive_entry_set_uid(e,in.i_uid); archive_entry_set_gid(e,in.i_gid);
 archive_entry_set_mtime(e,in.i_mtime,in.i_mtime_nsec);
 archive_entry_set_nlink(e,in.i_nlink); archive_entry_set_ino64(e,nid);
 archive_entry_set_rdev(e,in.u.i_rdev);
 int n=erofs_listxattr(&in,NULL,0); check(n,"list xattr size");
 if(n) {
  char *names=malloc(n); if(!names) die("xattr names allocation");
  check(erofs_listxattr(&in,names,n),"list xattrs");
  for(char *s=names;s<names+n;s+=strlen(s)+1) {
   int len=erofs_getxattr(&in,s,NULL,0); check(len,"xattr size");
   char *v=malloc(len?len:1); if(!v) die("xattr allocation");
   check(erofs_getxattr(&in,s,v,len),"read xattr");
   archive_entry_xattr_add_entry(e,s,v,len); free(v);
  } free(names);
 }
 int hard=0;
 if(!S_ISDIR(in.i_mode)&&in.i_nlink>1) {
  struct link *p=links;
  while(p && p->nid!=nid) p=p->next;
  if(p) { archive_entry_set_hardlink(e,p->path); hard=1; }
  else { p=calloc(1,sizeof(*p)); if(!p) die("link allocation"); p->nid=nid;p->path=strdup(path);p->next=links;links=p; }
 }
 if(S_ISLNK(in.i_mode)&&!hard) {
  char *v=calloc(1,in.i_size+1); if(!v) die("symlink allocation");
  check(erofs_pread(&in,v,in.i_size,0),"symlink read"); archive_entry_set_symlink(e,v); free(v);
 }
 archive_entry_set_size(e,S_ISREG(in.i_mode)&&!hard?in.i_size:0);
 if(archive_write_header(out,e)!=ARCHIVE_OK) die(archive_error_string(out));
 if(S_ISREG(in.i_mode)&&!hard) {
  char buf[65536];
  for(u64 off=0;off<in.i_size;) {
   size_t len=in.i_size-off; if(len>sizeof(buf)) len=sizeof(buf);
   check(erofs_pread(&in,buf,len,off),"file read");
   if(archive_write_data(out,buf,len)!=(ssize_t)len) die("archive data write"); off+=len;
  }
 }
 archive_entry_free(e);
 if(S_ISDIR(in.i_mode)) { struct walk w={.ctx={.dir=&in,.cb=child},.path=path,.depth=depth}; check(erofs_iterate_dir(&w.ctx,false),"iterate directory"); }
}
int main(int argc,char **argv) {
 if(argc!=2) die("usage: erofs-export IMAGE > archive.tar");
 erofs_init_configure(); cfg.c_dbg_lvl=-1;
 check(dev_open_ro(&sb,argv[1]),"open read-only source"); check(erofs_read_superblock(&sb),"superblock");
 out=archive_write_new(); check(archive_write_set_format_pax(out),"pax format");
 check(archive_write_open_fd(out,1),"stdout"); emit(sb.root_nid,".",0);
 check(archive_write_close(out),"close archive"); archive_write_free(out); erofs_put_super(&sb);dev_close(&sb); return 0;
}
