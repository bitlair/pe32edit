#ifndef __INCLUDES_H_
#define __INCLUDES_H_

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "inc/status.h"
#include "inc/format.h"
#include "lib/read_helper.h"

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif
#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif



#define NO_MEMORY_RETURN(x) { if (x == NULL) return STATUS_NO_MEMORY; }

#endif /* __PE32EDIT_H_ */
