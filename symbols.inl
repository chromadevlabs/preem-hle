bool DeviceIoControl(uint32_t device, uint32_t code, void* inBuf, uint32_t inBufSize, void* outBuf, uint32_t outBufSize, uint32_t bytesRet, void* lpOverlapped)
uint32_t device
uint32_t device['uint32_t', 'device']
uint32_t code
uint32_t code['uint32_t', 'code']
void* inBuf
void inBuf['void', 'inBuf']
uint32_t inBufSize
uint32_t inBufSize['uint32_t', 'inBufSize']
void* outBuf
void outBuf['void', 'outBuf']
uint32_t outBufSize
uint32_t outBufSize['uint32_t', 'outBufSize']
uint32_t bytesRet
uint32_t bytesRet['uint32_t', 'bytesRet']
void* lpOverlapped
void lpOverlapped['void', 'lpOverlapped']
bool
bool
bool['bool']
bool
bool['bool']
void CloseHandle(uint32_t handle)
uint32_t handle
uint32_t handle['uint32_t', 'handle']
uint32_t CreateEventW(void* attributes, bool reset, bool state, const wchar_t* name)
void* attributes
void attributes['void', 'attributes']
bool reset
bool reset['bool', 'reset']
bool state
bool state['bool', 'state']
const wchar_t* name
 wchar_t name['wchar_t', 'name']
uint32_t
uint32_t
uint32_t['uint32_t']
uint32_t
uint32_t['uint32_t']
uint32_t CreateFileW(const wchar_t* path, uint32_t access, uint32_t share, void* attr, uint32_t create, uint32_t flags, uint32_t temp)
const wchar_t* path
 wchar_t path['wchar_t', 'path']
uint32_t access
uint32_t access['uint32_t', 'access']
uint32_t share
uint32_t share['uint32_t', 'share']
void* attr
void attr['void', 'attr']
uint32_t create
uint32_t create['uint32_t', 'create']
uint32_t flags
uint32_t flags['uint32_t', 'flags']
uint32_t temp
uint32_t temp['uint32_t', 'temp']
uint32_t
uint32_t
uint32_t['uint32_t']
uint32_t
uint32_t['uint32_t']
uint32_t CreateMutexW(void* attributes, bool initialOwner, const wchar_t* name)
void* attributes
void attributes['void', 'attributes']
bool initialOwner
bool initialOwner['bool', 'initialOwner']
const wchar_t* name
 wchar_t name['wchar_t', 'name']
uint32_t
uint32_t
uint32_t['uint32_t']
uint32_t
uint32_t['uint32_t']
void Sleep(uint32_t time)
uint32_t time
uint32_t time['uint32_t', 'time']
uint32_t WaitForSingleObject(uint32_t handle, uint32_t ms)
uint32_t handle
uint32_t handle['uint32_t', 'handle']
uint32_t ms
uint32_t ms['uint32_t', 'ms']
uint32_t
uint32_t
uint32_t['uint32_t']
uint32_t
uint32_t['uint32_t']
char* strcpy(char* dst, const char* src)
char* dst
char dst['char', 'dst']
const char* src
 char src['char', 'src']
char*
char*
char['char']
void eglSwapIntervalNV()
void glEnableClientState(GLenum arr)
GLenum arr
GLenum arr['GLenum', 'arr']
void glDisableClientState(GLenum arr)
GLenum arr
GLenum arr['GLenum', 'arr']
void glVertexPointer(uint32_t size, GLenum type, uint32_t stride, const void* pointer)
uint32_t size
uint32_t size['uint32_t', 'size']
GLenum type
GLenum type['GLenum', 'type']
uint32_t stride
uint32_t stride['uint32_t', 'stride']
const void* pointer
 void pointer['void', 'pointer']
void glColorPointer()
void glClientActiveTexture()
void glTexCoordPointer()
void glDrawElements()
void glTexEnvf()
void glDepthRangef()
void glDepthMask()
void glDepthFunc()
void glCullFace()
void glEnable(GLenum feat)
GLenum feat
GLenum feat['GLenum', 'feat']
void glDisable(GLenum feat)
GLenum feat
GLenum feat['GLenum', 'feat']
void glGetIntegerv()
const char* glGetString()
const
const
[]
