/* folders.c 
 * Functions used to manage folders.
 * There is only one, it probably belongs elsewhere. 
 *
 * See the LICENSE file included with this distribution.
 */
#include <stdio.h>
#include <string.h>
#include "cf.h"
#include "folder.h"

#ifdef DEBUG
#endif

struct folder *findfolder(struct folder *folders, char *name) {
    struct folder *f;

    for(f = folders; f; f = f->next) {
        if(!strcmp(f->name, name))
            return(f);
    }

    return(NULL);
}

