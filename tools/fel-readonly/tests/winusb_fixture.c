/* SPDX-License-Identifier: MIT
 * PC-only DLL for ctypes ABI tests. No imports, DllMain, devices or syscalls.
 * All handles and data are synthetic. NEVER use this as a USB implementation.
 */
typedef unsigned char U8;
typedef unsigned short U16;
typedef unsigned int U32;
typedef unsigned long long U64;
#define API __declspec(dllexport)
#define FILE_HANDLE ((void *)0x1234567800000011ull)
#define USB_HANDLE ((void *)0x8765432100000022ull)
static U64 seen[32];
static U32 fault;
#pragma pack(push,1)
struct iface { U8 length,type,number,alternate,count,cls,subclass,protocol,index; };
#pragma pack(pop)
struct pipe { int type; U8 id; U16 packet; U8 interval; };
_Static_assert(sizeof(struct iface)==9,"interface ABI");
_Static_assert(sizeof(struct pipe)==12,"pipe ABI");
API void TestReset(void) { for(U32 i=0;i<32;++i)seen[i]=0; fault=0; }
API void TestFault(U32 f) { fault=f; }
API U64 TestGet(U32 i) { return i<32?seen[i]:0; }
API void *CreateFileW(const U16 *path,U32 access,U32 share,void *security,
                     U32 creation,U32 flags,void *template_file) {
    seen[0]=path!=0;seen[1]=access;seen[2]=share;seen[3]=creation;seen[4]=flags;
    seen[5]=security==0 && template_file==0;
    return fault==1 ? (void *)~0ull : FILE_HANDLE;
}
API int CloseHandle(void *handle) { seen[6]=(U64)handle;seen[7]++;return 1; }
API int WinUsb_Initialize(void *file,void **out) {
    seen[8]=(U64)file;
    if(fault==2)return 0;
    *out=USB_HANDLE;return 1;
}
API int WinUsb_Free(void *handle) { seen[9]=(U64)handle;seen[10]++;return 1; }
API int WinUsb_GetDescriptor(void *handle,U8 type,U8 index,U16 language,
                            U8 *buffer,U32 length,U32 *actual) {
    seen[11]=(U64)handle;seen[12]=type;seen[13]=index;seen[14]=language;
    if(length!=18)return 0;
    for(U32 i=0;i<18;++i)buffer[i]=0;
    buffer[0]=18;buffer[1]=1;buffer[8]=0x3a;buffer[9]=0x1f;buffer[10]=0xe8;buffer[11]=0xef;
    *actual=fault==3 ? 19 : 18;return 1;
}
API int WinUsb_QueryInterfaceSettings(void *handle,U8 alt,struct iface *out) {
    (void)handle;seen[15]=alt;
    out->length=9;out->type=4;out->number=0;out->alternate=0;out->count=2;
    out->cls=255;out->subclass=out->protocol=out->index=0;return 1;
}
API int WinUsb_QueryPipe(void *handle,U8 alt,U8 index,struct pipe *out) {
    (void)handle;(void)alt;
    out->type=2;out->id=index==0 ? 0x81 : 1;out->packet=512;out->interval=0;return 1;
}
API int WinUsb_SetPipePolicy(void *handle,U8 pipe,U32 policy,U32 size,const void *value) {
    (void)handle;(void)pipe;
    seen[16]++;
    if(policy==3) { if(size!=4)return 0;seen[17]=*(const U32 *)value; }
    else { if(size!=1 || *(const U8 *)value!=0)return 0;seen[18]|=1ull<<policy; }
    return fault==4?0:1;
}
API int WinUsb_WritePipe(void *handle,U8 pipe,const U8 *data,U32 length,U32 *actual,void *overlapped) {
    seen[19]=(U64)handle;seen[20]=pipe;seen[21]=length;seen[22]=overlapped==0;
    seen[23]=data[0];*actual=fault==5 ? length+1 : length;return fault==7?0:1;
}
API int WinUsb_ReadPipe(void *handle,U8 pipe,U8 *data,U32 length,U32 *actual,void *overlapped) {
    seen[24]=(U64)handle;seen[25]=pipe;seen[26]=length;seen[27]=overlapped==0;
    for(U32 i=0;i<length;++i)data[i]=(U8)i;
    *actual=fault==6 ? length+1 : length;return fault==7?0:1;
}
