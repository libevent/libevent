
#ifndef _EVENT2_BUFFER_COMPAT_H_
#define _EVENT2_BUFFER_COMPAT_H_

/** @file buffer_compat.h

	Obsolete and deprecated versions of the functions in buffer.h: provided
	only for backward compatibility.
 */


/**
   Obsolete alias for evbuffer_readln(buffer, NULL, EOL_STYLE_ANY).

   @deprecated This function is deprecated because its behavior is not correct
      for almost any protocol, and also because it's wholly subsumed by
      evbuffer_readln().

   @param buffer the evbuffer to read from
   @return pointer to a single line, or NULL if an error occurred

*/
char *evbuffer_readline(struct evbuffer *buffer);

/** Type definition for a callback that is invoked whenever data is added or
    removed from an evbuffer.

    An evbuffer may have one or more callbacks set at a time.  The order
    in which they are exectuded is undefined.

    A callback function may add more callbacks, or remove itself from the
    list of callbacks, or add or remove data from the buffer.  It may not
    remove another callback from the list.

    If a callback adds or removes data from the buffer or from another
    buffer, this can cause a recursive invocation of your callback or
    other callbacks.  If you ask for an infinite loop, you might just get
    one: watch out!

    @param buffer the buffer whose size has changed
    @param old_len the previous length of the buffer
    @param new_len the current length of the buffer
    @param arg a pointer to user data
*/
typedef void (*evbuffer_cb)(struct evbuffer *buffer, size_t old_len, size_t new_len, void *arg);

/**
  Replace all callbacks on an evbuffer with a single new callback, or
  remove them.

  Subsequent calls to evbuffer_setcb() replace callbacks set by previous
  calls.  Setting the callback to NULL removes any previously set callback.

  @deprecated This function is deprecated because it clears all previous
     callbacks set on the evbuffer, which can cause confusing behavior if
     multiple parts of the code all want to add their own callbacks on a
     buffer.  Instead, use evbuffer_add(), evbuffer_del(), and
     evbuffer_setflags() to manage your own evbuffer callbacks without
     interfering with callbacks set by others.

  @param buffer the evbuffer to be monitored
  @param cb the callback function to invoke when the evbuffer is modified,
            or NULL to remove all callbacks.
  @param cbarg an argument to be provided to the callback function
 */
void evbuffer_setcb(struct evbuffer *buffer, evbuffer_cb cb, void *cbarg);


/**
  Find a string within an evbuffer.

  @param buffer the evbuffer to be searched
  @param what the string to be searched for
  @param len the length of the search string
  @return a pointer to the beginning of the search string, or NULL if the search failed.
 */
unsigned char *evbuffer_find(struct evbuffer *buffer, const unsigned char *what, size_t len);

/** deprecated in favor of calling the functions directly */
#define EVBUFFER_LENGTH(x)	evbuffer_get_length(x)
/** deprecated in favor of calling the functions directly */
#define EVBUFFER_DATA(x)	evbuffer_pullup(x, -1)

#endif

