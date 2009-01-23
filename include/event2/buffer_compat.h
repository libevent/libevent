
#ifndef _EVENT2_BUFFER_COMPAT_H_
#define _EVENT2_BUFFER_COMPAT_H_

/** @file buffer_compat.h

	Obsolete and deprecated versions of the functions in buffer.h: provided
	only for backward compatibility.
 */


/**
   Obsolete alias for evbuffer_readln(buffer, NULL, EOL_STYLE_ANY).

   @param buffer the evbuffer to read from
   @return pointer to a single line, or NULL if an error occurred
*/
char *evbuffer_readline(struct evbuffer *buffer);

/**
  Replace all callbacks on an evbuffer with a single new callback, or
  remove them.

  Subsequent calls to evbuffer_setcb() replace callbacks set by previous
  calls.  Setting the callback to NULL removes any previously set callback.

  @param buffer the evbuffer to be monitored
  @param cb the callback function to invoke when the evbuffer is modified,
            or NULL to remove all callbacks.
  @param cbarg an argument to be provided to the callback function
 */
void evbuffer_setcb(struct evbuffer *buffer, evbuffer_cb cb, void *cbarg);

#endif

