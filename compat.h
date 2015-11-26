#ifndef __COMPAT_H__
#define __COMPAT_H__

#include <proto/dos.h>

#define sleep(secs) Delay((secs) * 50)

#endif /* __COMPAT_H__ */
