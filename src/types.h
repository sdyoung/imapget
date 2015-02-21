/* types.h 
 * Defines some primitive types used throughout imapget.
 * 
 * See the LICENSE file included with this disribution.
 */
#ifndef _TYPES_H
#define _TYPES_H

typedef enum { false = 0, true } bool;
enum authtype { autonegotiate = 0, cram_md5, digest_md5, login, 
                preauth };
enum readaction { delete_read, move_read, leave_read };
enum deliverytype { pipeto, mbox, maildir };

#endif /* !_TYPES_H */
