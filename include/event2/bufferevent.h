/*
 * Copyright (c) 2000-2007 Niels Provos <provos@citi.umich.edu>
 * Copyright (c) 2007-2009 Niels Provos and Nick Mathewson
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _EVENT2_BUFFEREVENT_H_
#define _EVENT2_BUFFEREVENT_H_

/** @file bufferevent.h

  Functions for buffering data for network sending or receiving.  Bufferevents
  are higher level than evbuffers: each has an underlying evbuffer for reading
  and one for writing, and callbacks that are invoked under certain
  circumstances.

  libevent provides an abstraction on top of the regular event callbacks.
  This abstraction is called a buffered event.  A buffered event provides
  input and output buffers that get filled and drained automatically.  The
  user of a buffered event no longer deals directly with the I/O, but
  instead is reading from input and writing to output buffers.

  Once initialized, the bufferevent structure can be used repeatedly with
  bufferevent_enable() and bufferevent_disable().

  When read enabled the bufferevent will try to read from the file descriptor
  and call the read callback.  The write callback is executed whenever the
  output buffer is drained below the write low watermark, which is 0 by
  default.

 */

#ifdef __cplusplus
extern "C" {
#endif

#include <event-config.h>
#ifdef _EVENT_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef _EVENT_HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

/* For int types. */
#include <event2/util.h>

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#endif


/* Just for error reporting - use other constants otherwise */
#define EVBUFFER_READ		0x01	/**< error encountered while reading */
#define EVBUFFER_WRITE		0x02	/**< error encountered while writing */
#define EVBUFFER_EOF		0x10	/**< eof file reached */
#define EVBUFFER_ERROR		0x20	/**< unrecoverable error encountered */
#define EVBUFFER_TIMEOUT	0x40	/**< user specified timeout reached */
struct bufferevent;
struct event_base;
struct evbuffer;

/**
   type definition for the read or write callback.

   The read callback is triggered when new data arrives in the input
   buffer and the amount of readable data exceed the low watermark
   which is 0 by default.

   The write callback is triggered if the write buffer has been
   exhausted or fell below its low watermark.

   @param bev the bufferevent that triggered the callback
   @param ctx the user specified context for this bufferevent
 */
/* XXXX we should rename this to bufferevent_cb; evbuffercb implies that it's
 * a cb on an evbuffer. We should retain the old name in bufferevent_compat. */
typedef void (*evbuffercb)(struct bufferevent *bev, void *ctx);

/**
   type defintion for the error callback of a bufferevent.

   The error callback is triggered if either an EOF condition or another
   unrecoverable error was encountered.

   @param bev the bufferevent for which the error condition was reached
   @param what a conjunction of flags: EVBUFFER_READ or EVBUFFER write to
	  indicate if the error was encountered on the read or write path,
	  and one of the following flags: EVBUFFER_EOF, EVBUFFER_ERROR or
	  EVBUFFER_TIMEOUT.
   @param ctx the user specified context for this bufferevent
*/
/* XXXX we should rename this to bufferevent_error_cb; see above. */
typedef void (*everrorcb)(struct bufferevent *bev, short what, void *ctx);

/** Options that can be specified when creating a bufferevent */
enum bufferevent_options {
	/** If set, we close the underlying file
	 * descriptor/bufferevent/whatever when this bufferevent is freed. */
	BEV_OPT_CLOSE_ON_FREE = (1<<0),

	/** If set, and threading is enabled, operations on this bufferevent
	 * are protected by a lock */
	BEV_OPT_THREADSAFE = (1<<1),
};

/**
  Create a new socket bufferevent over an existing socket.

  @param base the event base to associate with the new bufferevent.
  @param fd the file descriptor from which data is read and written to.
  		This file descriptor is not allowed to be a pipe(2).
  @return a pointer to a newly allocated bufferevent struct, or NULL if an
          error occurred
  @see bufferevent_free()
  */
struct bufferevent *bufferevent_socket_new(struct event_base *base, evutil_socket_t fd, enum bufferevent_options options);

/**
  Assign a bufferevent to a specific event_base.

  @param base an event_base returned by event_init()
  @param bufev a bufferevent struct returned by bufferevent_new()
  @return 0 if successful, or -1 if an error occurred
  @see bufferevent_new()
 */
int bufferevent_base_set(struct event_base *base, struct bufferevent *bufev);


/**
  Assign a priority to a bufferevent.

  @param bufev a bufferevent struct
  @param pri the priority to be assigned
  @return 0 if successful, or -1 if an error occurred
  */
int bufferevent_priority_set(struct bufferevent *bufev, int pri);


/**
  Deallocate the storage associated with a bufferevent structure.

  @param bufev the bufferevent structure to be freed.
  */
void bufferevent_free(struct bufferevent *bufev);


/**
  Changes the callbacks for a bufferevent.

  @param bufev the bufferevent object for which to change callbacks
  @param readcb callback to invoke when there is data to be read, or NULL if
         no callback is desired
  @param writecb callback to invoke when the file descriptor is ready for
         writing, or NULL if no callback is desired
  @param errorcb callback to invoke when there is an error on the file
         descriptor
  @param cbarg an argument that will be supplied to each of the callbacks
         (readcb, writecb, and errorcb)
  @see bufferevent_new()
  */
void bufferevent_setcb(struct bufferevent *bufev,
    evbuffercb readcb, evbuffercb writecb, everrorcb errorcb, void *cbarg);

/**
  Changes the file descriptor on which the bufferevent operates.

  @param bufev the bufferevent object for which to change the file descriptor
  @param fd the file descriptor to operate on
*/
void bufferevent_setfd(struct bufferevent *bufev, evutil_socket_t fd);

/**
  Write data to a bufferevent buffer.

  The bufferevent_write() function can be used to write data to the file
  descriptor.  The data is appended to the output buffer and written to the
  descriptor automatically as it becomes available for writing.

  @param bufev the bufferevent to be written to
  @param data a pointer to the data to be written
  @param size the length of the data, in bytes
  @return 0 if successful, or -1 if an error occurred
  @see bufferevent_write_buffer()
  */
int bufferevent_write(struct bufferevent *bufev,
    const void *data, size_t size);


/**
  Write data from an evbuffer to a bufferevent buffer.  The evbuffer is
  being drained as a result.

  @param bufev the bufferevent to be written to
  @param buf the evbuffer to be written
  @return 0 if successful, or -1 if an error occurred
  @see bufferevent_write()
 */
int bufferevent_write_buffer(struct bufferevent *bufev, struct evbuffer *buf);


/**
  Read data from a bufferevent buffer.

  The bufferevent_read() function is used to read data from the input buffer.

  @param bufev the bufferevent to be read from
  @param data pointer to a buffer that will store the data
  @param size the size of the data buffer, in bytes
  @return the amount of data read, in bytes.
 */
size_t bufferevent_read(struct bufferevent *bufev, void *data, size_t size);

/**
  Read data from a bufferevent buffer into an evbuffer.  This avoids
  memory copies.

  @param bufev the bufferevent to be read from
  @param buf the evbuffer to which to add data
  @return 0 if successful, or -1 if an error occurred.
 */
int bufferevent_read_buffer(struct bufferevent *bufev, struct evbuffer *buf);

/**
   Returns the input buffer.

   The user MUST NOT set the callback on this buffer.

   @param bufev the buffervent from which to get the evbuffer
   @return the evbuffer object for the input buffer
 */

struct evbuffer *bufferevent_get_input(struct bufferevent *bufev);

/**
   Returns the outut buffer.

   The user MUST NOT set the callback on this buffer.

   When filters are being used, the filters need to be manually
   triggered if the output buffer was manipulated.

   @param bufev the buffervent from which to get the evbuffer
   @return the evbuffer object for the output buffer
 */

struct evbuffer *bufferevent_get_output(struct bufferevent *bufev);

/**
  Enable a bufferevent.

  @param bufev the bufferevent to be enabled
  @param event any combination of EV_READ | EV_WRITE.
  @return 0 if successful, or -1 if an error occurred
  @see bufferevent_disable()
 */
int bufferevent_enable(struct bufferevent *bufev, short event);

/**
  Disable a bufferevent.

  @param bufev the bufferevent to be disabled
  @param event any combination of EV_READ | EV_WRITE.
  @return 0 if successful, or -1 if an error occurred
  @see bufferevent_enable()
 */
int bufferevent_disable(struct bufferevent *bufev, short event);


/**
  Set the read and write timeout for a buffered event.

  @param bufev the bufferevent to be modified
  @param timeout_read the read timeout, or NULL
  @param timeout_write the write timeout, or NULL
 */
void bufferevent_set_timeouts(struct bufferevent *bufev,
    const struct timeval *timeout_read, const struct timeval *timeout_write);

/**
  Sets the watermarks for read and write events.

  On input, a bufferevent does not invoke the user read callback unless
  there is at least low watermark data in the buffer.   If the read buffer
  is beyond the high watermark, the buffevent stops reading from the network.

  On output, the user write callback is invoked whenever the buffered data
  falls below the low watermark.  Filters that write to this bufev will try
  not to write more bytes to this buffer than the high watermark would allow,
  except when flushing.

  @param bufev the bufferevent to be modified
  @param events EV_READ, EV_WRITE or both
  @param lowmark the lower watermark to set
  @param highmark the high watermark to set
*/

void bufferevent_setwatermark(struct bufferevent *bufev, short events,
    size_t lowmark, size_t highmark);

/** macro for getting access to the input buffer of a bufferevent */
#define EVBUFFER_INPUT(x)	bufferevent_get_input(x)
/** macro for getting access to the output buffer of a bufferevent */
#define EVBUFFER_OUTPUT(x)	bufferevent_get_output(x)

/**
   Flags that can be passed into filters to let them know how to
   deal with the incoming data.
*/
enum bufferevent_flush_mode {
	/** usually set when processing data */
	BEV_NORMAL = 0,

	/** want to checkpoint all data sent. */
	BEV_FLUSH = 1,

	/** encountered EOF on read or done sending data */
	BEV_FINISHED = 2,
};

/**
   Triggers the bufferevent to produce more
   data if possible.

   @param bufev the bufferevent object
   @param iotype either EV_READ or EV_WRITE or both.
   @param state either BEV_NORMAL or BEV_FLUSH or BEV_FINISHED
   @return -1 on failure, 0 if no data was produces, 1 if data was produced
 */
int bufferevent_flush(struct bufferevent *bufev,
    short iotype,
    enum bufferevent_flush_mode state);

/**
   Support for filtering input and output of bufferevents.
 */

/**
   Values that filters can return.
 */
enum bufferevent_filter_result {
	/** everything is okay */
	BEV_OK = 0,

	/** the filter needs to read more data before output */
	BEV_NEED_MORE = 1,

	/** the filter enountered a critical error, no further data
	    can be processed. */
	BEV_ERROR = 2
};

/** A callback function to implement a filter for a bufferevent.

    @param src An evbuffer to drain data from.
    @param dst An evbuffer to add data to.
    @param limit A suggested upper bound of bytes to write to dst.
       The filter may ignore this value, but doing so means that
       it will overflow the high-water mark associated with dst.
       -1 means "no limit".
    @param state Whether we should write data as may be convenient
       (BEV_NORMAL), or flush as much data as we can (BEV_FLUSH),
       or flush as much as we can, possibly including an end-of-stream
       marker (BEF_FINISH).
    @param ctx A user-supplied pointer.

    @return BEV_OK if we wrote some data; BEV_NEED_MORE if we can't
       produce any more output until we get some input; and BEV_ERROR
       on an error.
 */
typedef enum bufferevent_filter_result (*bufferevent_filter_cb)(
    struct evbuffer *src, struct evbuffer *dst, ssize_t dst_limit,
    enum bufferevent_flush_mode mode, void *ctx);

/**
   Allocate a new filtering bufferevent on top of an existing bufferevent.

   @param underlying the underlying bufferevent.
   @param input_filter The filter to apply to data we read from the underlying
     bufferevent
   @param output_filter The filer to apply to data we write to the underlying
     bufferevent
   @param options A bitfield of bufferevent options.
   @param free_context A function to use to free the filter context when
     this bufferevent is freed.
   @param ctx A context pointer to pass to the filter functions.
 */
struct bufferevent *
bufferevent_filter_new(struct bufferevent *underlying,
		       bufferevent_filter_cb input_filter,
		       bufferevent_filter_cb output_filter,
		       enum bufferevent_options options,
		       void (*free_context)(void *),
		       void *ctx);

/**
   Allocate a pair of linked bufferevents.  The bufferevents behave as would
   two bufferevent_sock instances connected to opposite ends of a
   socketpair(), except that no internel socketpair is allocated.

   @param base The event base to associate with the socketpair.
   @param options A set of options for this bufferevent
   @param pair A pointer to an array to hold the two new bufferevent objects.
   @return 0 on success, -1 on failure.
 */
int
bufferevent_pair_new(struct event_base *base, enum bufferevent_options options,
    struct bufferevent *pair[2]);

#ifdef __cplusplus
}
#endif

#endif /* _EVENT2_BUFFEREVENT_H_ */
