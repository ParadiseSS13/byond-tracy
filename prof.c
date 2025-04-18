/* c11 minimum */
#if !defined(__STDC_VERSION__) || (__STDC_VERSION__ < 201112L)
#	pragma message("minimum supported c standard is c11")
#endif

#if defined(__cplusplus)
#	pragma message("compiling as c++ is ill-advised")
#endif

#if defined(__STDC_NO_ATOMICS__)
#	error C11 atomics support required (if compiling on windows with MSVC, pass /experimental:c11atomics to cl.exe)
#endif

/* platform identification */
#if defined(_WIN32)
#	define UTRACY_WINDOWS
#	define _CRT_SECURE_NO_WARNINGS
#	if defined(_WIN64)
#		error 64 bit not supported
#	endif
#	if !defined(_WIN32_WINNT)
#		define _WIN32_WINNT 0x0601
#	endif
#	if !defined(WINVER)
#		define WINVER 0x0601
#	endif
#elif defined(__linux__)
#	define UTRACY_LINUX
#	if defined(__x86_64__)
#		error 64 bit not supported
#	endif
#else
#	error platform not detected
#endif

/* compiler identification */
#if defined(__clang__)
#	define UTRACY_CLANG
#elif defined(__GNUC__)
#	define UTRACY_GCC
#elif defined(_MSC_VER)
#	define UTRACY_MSVC
#else
#	error compiler not detected
#endif

#if defined(UTRACY_CLANG) || defined(UTRACY_GCC)
#	define likely(expr) __builtin_expect(((expr) != 0), 1)
#	define unlikely(expr) __builtin_expect(((expr) != 0), 0)
#else
#	define likely(expr) (expr)
#	define unlikely(expr) (expr)
#endif
#define UTRACY_ALIGN_DOWN(ptr, size) ((void *) ((uintptr_t) (ptr) & (~((size) - 1))))

/* data type size check */
_Static_assert(sizeof(void *) == 4, "incorrect size");
_Static_assert(sizeof(int) == 4, "incorrect size");
_Static_assert(sizeof(long long) == 8, "incorrect size");

/* linkage and exports */
#if defined(UTRACY_WINDOWS)
#	if defined(UTRACY_CLANG) || defined(UTRACY_GCC)
#		define UTRACY_INTERNAL static
#		define UTRACY_EXTERNAL __attribute__((visibility("default"))) __attribute__((dllexport))
#		define UTRACY_INLINE inline __attribute__((always_inline))
#	elif defined(UTRACY_MSVC)
#		define UTRACY_INTERNAL static
#		define UTRACY_EXTERNAL __declspec(dllexport)
#		define UTRACY_INLINE inline __forceinline
#	endif
#elif defined(UTRACY_LINUX)
#	if defined(UTRACY_CLANG) || defined(UTRACY_GCC)
#		define UTRACY_INTERNAL static
#		define UTRACY_EXTERNAL __attribute__((visibility("default")))
#		define UTRACY_INLINE inline __attribute__((always_inline))
#	endif
#endif

/* calling conventions */
#if defined(UTRACY_WINDOWS)
#	define UTRACY_WINDOWS_CDECL __cdecl
#	define UTRACY_WINDOWS_STDCALL __stdcall
#	define UTRACY_WINDOWS_THISCALL __thiscall
#	define UTRACY_LINUX_CDECL
#	define UTRACY_LINUX_STDCALL
#	define UTRACY_LINUX_THISCALL
#	define UTRACY_LINUX_REGPARM(a)
#elif defined(UTRACY_LINUX)
#	define UTRACY_WINDOWS_CDECL
#	define UTRACY_WINDOWS_STDCALL
#	define UTRACY_WINDOWS_THISCALL
#	define UTRACY_LINUX_CDECL __attribute__((cdecl))
#	define UTRACY_LINUX_STDCALL __attribute__((stdcall))
#	define UTRACY_LINUX_THISCALL __attribute__((thiscall))
#	define UTRACY_LINUX_REGPARM(a) __attribute__((regparm(a)))
#endif

/* headers */
#if defined(UTRACY_WINDOWS)
#	define NOMINMAX
#	include <winsock2.h>
#	include <ws2tcpip.h>
#	include <windows.h>
#   include <io.h>
#elif defined(UTRACY_LINUX)
#	define _GNU_SOURCE
#	include <errno.h>
#	include <unistd.h>
#	include <time.h>
#	include <sys/syscall.h>
#	include <sys/types.h>
#	include <sys/socket.h>
#	include <sys/mman.h>
#	include <sys/stat.h>
#	include <sys/eventfd.h>
#	include <netdb.h>
#	include <pthread.h>
#	include <dlfcn.h>
#	include <link.h>
#	include <netinet/ip.h>
#	include <arpa/inet.h>
#	include <poll.h>
#	include <fcntl.h>
/* avoid including stdlib.h */
char *getenv(char const *);
#endif

#include <stddef.h>
#include <assert.h>
#include <stdio.h>
#include <stdbool.h>
#include <threads.h>
#include <stdatomic.h>

#if (__STDC_HOSTED__ == 1)
#	include <stdlib.h>
#	include <string.h>
#endif

#if (__STDC_HOSTED__ == 0)
void *memset(void *const a, int value, size_t len) {
	for(size_t i=0; i<len; i++) {
		*((char *) a + i) = value;
	}
	return a;
}

void *memcpy(void *const restrict dst, void const *const restrict src, size_t len) {
	for(size_t i=0; i<len; i++) {
		*((char *) dst + i) = *((char *) src + i);
	}
	return dst;
}

int memcmp(void const *a, void const *b, size_t len) {
	for(size_t i=0; i<len; i++) {
		char unsigned _a = *(char unsigned *) a;
		char unsigned _b = *(char unsigned *) b;
		if(_a != _b) {
			return (_a - _b);
		}
	}
	return 0;
}

size_t strlen(char const *const a) {
	size_t len = 0;
	for(char const *p=a; *p; p++) {
		len++;
	}
	return len;
}
#endif

#if defined(max)
#	undef max
#endif
#if defined(UTRACY_CLANG) || defined(UTRACY_GCC)
#	define max(a, b) ({ \
		__typeof__(a) _a = (a); \
		__typeof__(b) _b = (b); \
		_a > _b ? _a : _b; \
	})
#elif defined(UTRACY_MSVC)
#	define max(a, b) (((a) > (b)) ? (a) : (b))
#endif

#if defined(min)
#	undef min
#endif
#if defined(UTRACY_CLANG) || defined(UTRACY_GCC)
#	define min(a, b) ({ \
		__typeof__(a) _a = (a); \
		__typeof__(b) _b = (b); \
		_a < _b ? _a : _b; \
	})
#elif defined(UTRACY_MSVC)
#	define min(a, b) (((a) < (b)) ? (a) : (b))
#endif

#if defined(UTRACY_CLANG) || defined(UTRACY_GCC)
#	if __has_builtin(__builtin_memcpy)
#		define UTRACY_MEMCPY __builtin_memcpy
#	else
#		define UTRACY_MEMCPY memcpy
#	endif
#	if __has_builtin(__builtin_memset)
#		define UTRACY_MEMSET __builtin_memset
#	else
#		define UTRACY_MEMSET memset
#	endif
#	if __has_builtin(__builtin_memcmp)
#		define UTRACY_MEMCMP __builtin_memcmp
#	else
#		define UTRACY_MEMCMP memcmp
#	endif
#else
#	define UTRACY_MEMCPY memcpy
#	define UTRACY_MEMSET memset
#	define UTRACY_MEMCMP memcmp
#endif

#if defined(UTRACY_LINUX)
#	define _fileno fileno
#endif


/* debugging */
#if defined(UTRACY_DEBUG) || defined(DEBUG)
#	include <stdio.h>
#	define LOG_DEBUG_ERROR fprintf(stderr, "err: %s %s:%d\n", __func__, __FILE__, __LINE__)
#	define LOG_INFO(...) fprintf(stdout, __VA_ARGS__)
#else
#	define LOG_DEBUG_ERROR
#	define LOG_INFO(...)
#endif

/* config */
#define UTRACY_L1_LINE_SIZE (64)
#define UTRACY_PAGE_SIZE (4096)

#define EVENT_QUEUE_CAPACITY (1u << 18u)
_Static_assert((EVENT_QUEUE_CAPACITY & (EVENT_QUEUE_CAPACITY - 1)) == 0, "EVENT_QUEUE_CAPACITY must be a power of 2");

/* byond types */
struct object {
	union {
		int unsigned padding;
		char unsigned type;
	};
	union {
		int unsigned i;
		float f;
	};
};

struct string {
	char *data;
	int unsigned id;
	struct string *left;
	struct string *right;
	int unsigned refcount;
	int unsigned unk0;
	int unsigned len;
};

struct procdef {
	int unsigned path;
	int unsigned name;
	int unsigned desc;
	int unsigned category;
	int unsigned flags;
	int unsigned unk0;
	int unsigned bytecode;
	int unsigned locals;
	int unsigned parameters;
};

struct misc {
	struct {
		short unsigned len;
		int unsigned unk0;
		int unsigned *bytecode;
	} bytecode;
	struct {
		short unsigned len;
		int unsigned unk0;
		int unsigned *locals;
	} locals;
	struct {
		short unsigned len;
		int unsigned unk0;
		int unsigned *params;
	} params;
};

struct proc {
	int unsigned procdef;
	char unsigned flags;
	char unsigned supers;
	short unsigned unused;
	struct object usr;
	struct object src;
	struct execution_context *ctx;
	int unsigned sequence;
	void (*callback)(struct object, int unsigned);
	int unsigned callback_arg;
	int unsigned argc;
	struct object *argv;
	int unsigned unk0;
};

/* byond type size check */
_Static_assert(sizeof(struct object) == 8, "incorrect size");
_Static_assert(sizeof(struct string) == 28, "incorrect size");
_Static_assert(sizeof(struct procdef) >= 4, "incorrect size");
_Static_assert(sizeof(struct misc) == 36, "incorrect size");
_Static_assert(sizeof(struct proc) >= 4, "incorrect size");

/* queue */
#define atomic_load_relaxed(a) atomic_load_explicit((a), memory_order_relaxed)
#define atomic_load_acquire(a) atomic_load_explicit((a), memory_order_acquire)
#define atomic_store_seqcst(a, b) atomic_store_explicit((a), (b), memory_order_seq_cst)
#define atomic_store_release(a, b) atomic_store_explicit((a), (b), memory_order_release)

// Event pipe structure using C11 primitives
typedef struct event_pipe {
    atomic_bool signaled;
    mtx_t mutex;
    cnd_t condition;
    bool manual_reset;
} event_pipe_t;

struct event_zone_begin {
	int unsigned tid;
	int unsigned srcloc;
	_Alignas(8) long long timestamp;
};

struct event_zone_end {
	int unsigned tid;
	_Alignas(8) long long timestamp;
};

struct event_zone_color {
	int unsigned tid;
	int unsigned color;
};

struct event_frame_mark {
	void *name;
	_Alignas(8) long long timestamp;
};

struct event_plot {
	void *name;
	float f;
	_Alignas(8) long long timestamp;
};

struct event {
	char unsigned type;
	union {
		struct event_zone_begin zone_begin;
		struct event_zone_end zone_end;
		struct event_zone_color zone_color;
		struct event_frame_mark frame_mark;
		struct event_plot plot;
	};
};

/* data */
static struct {
	struct string ***strings;
	int unsigned *strings_len;
	struct misc ***miscs;
	int unsigned *miscs_len;
	/* procdef array address */
	char **procdefs;
	/* procdef array length */
	int unsigned *procdefs_len;
	/* procdef descriptor */
	struct {
		/* total size */
		int unsigned size;
		/* offsets */
		int unsigned path;
		int unsigned bytecode;
	} procdef_desc;
	void *exec_proc;
	struct object (UTRACY_WINDOWS_CDECL UTRACY_LINUX_REGPARM(3) *orig_exec_proc)(struct proc *);
	void *server_tick;
	int (UTRACY_WINDOWS_STDCALL UTRACY_LINUX_CDECL *orig_server_tick)(void);
	void *send_maps;
	void (UTRACY_WINDOWS_CDECL UTRACY_LINUX_CDECL *orig_send_maps)(void);
	_Alignas(UTRACY_PAGE_SIZE) struct {
		char exec_proc[32];
		char server_tick[32];
		char send_maps[32];
	} trampoline;
} byond;

static struct {
	struct {
		long long init_begin;
		long long init_end;
		double multiplier;
		long long resolution;
		long long delay;
		long long epoch;
		long long exec_time;
	} info;

	thrd_t thread;
    event_pipe_t* quit;

	FILE* fstream;

	struct {
		int unsigned producer_tail_cache;
		int unsigned consumer_head_cache;
		struct event events[EVENT_QUEUE_CAPACITY];

		_Alignas(UTRACY_L1_LINE_SIZE) atomic_uint head;
		_Alignas(UTRACY_L1_LINE_SIZE) atomic_uint tail;
		_Alignas(UTRACY_L1_LINE_SIZE) int padding;
	} queue;
} utracy;

event_pipe_t* create_event_pipe(bool manual_reset, bool initial_state) {
    event_pipe_t* pipe = malloc(sizeof(event_pipe_t));
    if (!pipe) {
        return NULL;
    }

    if (mtx_init(&pipe->mutex, mtx_plain) != thrd_success) {
        free(pipe);
        return NULL;
    }

    if (cnd_init(&pipe->condition) != thrd_success) {
        mtx_destroy(&pipe->mutex);
        free(pipe);
        return NULL;
    }

    atomic_init(&pipe->signaled, initial_state);
    pipe->manual_reset = manual_reset;
    return pipe;
}

void close_event_pipe(event_pipe_t* pipe) {
    if (pipe) {
        cnd_destroy(&pipe->condition);
        mtx_destroy(&pipe->mutex);
        free(pipe);
    }
}

int wait_for_event_pipe(event_pipe_t* pipe, int timeout_ms) {
    if (!pipe) {
        return -1;
    }

    int result = -1;
    mtx_lock(&pipe->mutex);
    
    if (!atomic_load(&pipe->signaled)) {
        if (timeout_ms < 0) {
            // Wait indefinitely
            while (!atomic_load(&pipe->signaled)) {
                if (cnd_wait(&pipe->condition, &pipe->mutex) != thrd_success) {
                    goto cleanup;
                }
            }
            result = 0;
        } else {
            // Wait with timeout
            struct timespec ts;
            timespec_get(&ts, TIME_UTC);
            ts.tv_sec += timeout_ms / 1000;
            ts.tv_nsec += (timeout_ms % 1000) * 1000000;
            if (ts.tv_nsec >= 1000000000) {
                ts.tv_sec += 1;
                ts.tv_nsec -= 1000000000;
            }

            while (!atomic_load(&pipe->signaled)) {
                int wait_result = cnd_timedwait(&pipe->condition, &pipe->mutex, &ts);
                if (wait_result == thrd_timedout) {
                    result = 1;  // Timeout
                    goto cleanup;
                } else if (wait_result != thrd_success) {
                    goto cleanup;
                }
            }
            result = 0;
        }
    } else {
        result = 0;
    }

    if (result == 0 && !pipe->manual_reset) {
        atomic_store(&pipe->signaled, false);
    }

cleanup:
    mtx_unlock(&pipe->mutex);
    return result;
}

void set_event_pipe(event_pipe_t* pipe) {
    if (!pipe) {
        return;
    }

    mtx_lock(&pipe->mutex);
    atomic_store(&pipe->signaled, true);
    cnd_broadcast(&pipe->condition);
    mtx_unlock(&pipe->mutex);
}

/* queue api */
UTRACY_INTERNAL UTRACY_INLINE
int event_queue_init(void) {
    utracy.queue.producer_tail_cache = 0;
    utracy.queue.consumer_head_cache = 0;
	atomic_store_seqcst(&utracy.queue.head, 1);
	atomic_store_seqcst(&utracy.queue.tail, 0);
    return 0;
}

UTRACY_INTERNAL UTRACY_INLINE
void event_queue_push(struct event const *const event) {
    int unsigned store = atomic_load_relaxed(&utracy.queue.head);
    int unsigned next_store = store + 1;

    if(next_store == EVENT_QUEUE_CAPACITY) {
        next_store = 0;
    }

    while(unlikely(next_store == utracy.queue.producer_tail_cache)) {
        utracy.queue.producer_tail_cache = atomic_load_acquire(&utracy.queue.tail);
    }

    utracy.queue.events[store] = *event;

    atomic_store_release(&utracy.queue.head, next_store);
}

UTRACY_INTERNAL UTRACY_INLINE
int event_queue_pop(struct event *const event) {
    int unsigned load = atomic_load_relaxed(&utracy.queue.tail);
    int unsigned next_load = load + 1;

    if(load == utracy.queue.consumer_head_cache) {
        utracy.queue.consumer_head_cache = atomic_load_acquire(&utracy.queue.head);
        if(load == utracy.queue.consumer_head_cache) {
            return -1;
        }
    }

    *event = utracy.queue.events[load];

    if(next_load == EVENT_QUEUE_CAPACITY) {
        next_load = 0;
    }

    atomic_store_release(&utracy.queue.tail, next_load);
    return 0;
}

/* profiler */
UTRACY_INTERNAL UTRACY_INLINE
long long utracy_tsc(void) {
#if defined(UTRACY_CLANG) || defined(UTRACY_GCC)
	return (long long) __builtin_ia32_rdtsc();
#elif defined(UTRACY_MSVC)
	return (long long) __rdtsc();
#else
	int unsigned eax, edx;
	__asm__ __volatile__("rdtsc;" :"=a"(eax), "=d"(edx));
	return ((long long) edx << 32) + eax;
#endif
}

#if defined(UTRACY_LINUX)
static int unsigned linux_main_tid;
#endif

UTRACY_INTERNAL UTRACY_INLINE
int unsigned utracy_tid(void) {
#if defined(UTRACY_WINDOWS)
#	if defined(UTRACY_CLANG) || defined(UTRACY_GCC)

	int unsigned tid;
	__asm__("mov %%fs:0x24, %0;" :"=r"(tid));
	return tid;

#	elif defined(UTRACY_MSVC)

	__asm {
		mov eax, fs:[0x24];
	}

#	else

	return GetCurrentThreadId();

#	endif
#elif defined(UTRACY_LINUX)
	/* too damn slow
	return syscall(__NR_gettid); */
	return linux_main_tid;
#endif
}

UTRACY_INTERNAL
double calibrate_multiplier(void) {
#if defined(UTRACY_WINDOWS)
	LARGE_INTEGER li_freq, li_t0, li_t1;
	if(0 == QueryPerformanceFrequency(&li_freq)) {
		LOG_DEBUG_ERROR;
		return 1.0;
	}

	if(0 == QueryPerformanceCounter(&li_t0)) {
		LOG_DEBUG_ERROR;
		return 1.0;
	}

	long long clk0 = utracy_tsc();

	Sleep(100);

	if(0 == QueryPerformanceCounter(&li_t1)) {
		LOG_DEBUG_ERROR;
		return 1.0;
	}

	long long clk1 = utracy_tsc();

	double const freq = li_freq.QuadPart;
	double const t0 = li_t0.QuadPart;
	double const t1 = li_t1.QuadPart;
	double const dt = ((t1 - t0) * 1000000000.0) / freq;
	double const dclk = clk1 - clk0;

	if(clk0 >= clk1) {
		LOG_DEBUG_ERROR;
		return 1.0;
	}

	if(t0 >= t1) {
		LOG_DEBUG_ERROR;
		return 1.0;
	}

	if(0.0 >= dclk) {
		LOG_DEBUG_ERROR;
		return 1.0;
	}

	return dt / dclk;

#elif defined(UTRACY_LINUX)
	struct timespec ts_t0, ts_t1;

interrupted:
	if(-1 == clock_gettime(CLOCK_MONOTONIC_RAW, &ts_t0)) {
		LOG_DEBUG_ERROR;
		return 1.0;
	}

	long long clk0 = utracy_tsc();

	if(-1 == usleep(100000)) {
		LOG_DEBUG_ERROR;

		if(EINTR == errno) {
			goto interrupted;
		}

		return 1.0;
	}

	if(-1 == clock_gettime(CLOCK_MONOTONIC_RAW, &ts_t1)) {
		LOG_DEBUG_ERROR;
		return 1.0;
	}

	long long clk1 = utracy_tsc();

	double const t0 = ts_t0.tv_sec * 1000000000.0 + ts_t0.tv_nsec;
	double const t1 = ts_t1.tv_sec * 1000000000.0 + ts_t1.tv_nsec;
	double const dt = t1 - t0;
	double const dclk = clk1 - clk0;

	if(clk0 >= clk1) {
		LOG_DEBUG_ERROR;
		return 1.0;
	}

	if(t0 >= t1) {
		LOG_DEBUG_ERROR;
		return 1.0;
	}

	if(0.0 >= dclk) {
		LOG_DEBUG_ERROR;
		return 1.0;
	}

	return dt / dclk;

#endif
}

UTRACY_INTERNAL
long long calibrate_resolution(void) {
	/* many iterations may be required to allow the thread time to migrate
	  to a suitable cpu / C-state / P-state */
	int const iterations = 1000000;
	long long resolution = 0x7FFFFFFFFFFFFFFFll;

	for(int i=0; i<iterations; i++) {
		long long clk0 = utracy_tsc();
		long long clk1 = utracy_tsc();
		long long dclk = clk1 - clk0;
		resolution = dclk < resolution ? dclk : resolution;
	}

	return resolution;
}

/* seconds since unix epoch */
UTRACY_INTERNAL
long long unix_timestamp(void) {
#if defined(UTRACY_WINDOWS)
	/* thanks Ian Boyd https://stackoverflow.com/a/46024468 */
	long long const UNIX_TIME_START = 0x019DB1DED53E8000ll;
	long long const TICKS_PER_SECOND = 10000000ll;

	FILETIME ft_timestamp;
	GetSystemTimeAsFileTime(&ft_timestamp);

	LARGE_INTEGER li_timestamp = {
		.LowPart = ft_timestamp.dwLowDateTime,
		.HighPart = ft_timestamp.dwHighDateTime
	};

	return (li_timestamp.QuadPart - UNIX_TIME_START) / TICKS_PER_SECOND;

#elif defined(UTRACY_LINUX)
	struct timespec t;

	if(-1 == clock_gettime(CLOCK_REALTIME, &t)) {
		LOG_DEBUG_ERROR;
		return 0;
	}

	return t.tv_sec;
#endif
}

#define UTRACY_EVT_ZONEBEGIN (15)
#define UTRACY_EVT_ZONEEND (17)
#define UTRACY_EVT_PLOTDATA (43)
#define UTRACY_EVT_THREADCONTEXT (57)
#define UTRACY_EVT_ZONECOLOR (62)
#define UTRACY_EVT_FRAMEMARKMSG (64)

struct utracy_source_location {
	char const *name;
	char const *function;
	char const *file;
	int unsigned line;
	int unsigned color;
};

static struct utracy_source_location srclocs[0x14002];

UTRACY_INTERNAL UTRACY_INLINE
void utracy_emit_zone_begin(int unsigned proc) {
	event_queue_push(&(struct event) {
		.type = UTRACY_EVT_ZONEBEGIN,
		.zone_begin.tid = utracy_tid(),
		.zone_begin.timestamp = utracy_tsc(),
		.zone_begin.srcloc = proc/*(void *) srcloc*/
	});
}

UTRACY_INTERNAL UTRACY_INLINE
void utracy_emit_zone_end(void) {
	event_queue_push(&(struct event) {
		.type = UTRACY_EVT_ZONEEND,
		.zone_end.tid = utracy_tid(),
		.zone_end.timestamp = utracy_tsc()
	});
}

UTRACY_INTERNAL UTRACY_INLINE
void utracy_emit_zone_color(int unsigned color) {
	event_queue_push(&(struct event) {
		.type = UTRACY_EVT_ZONECOLOR,
		.zone_color.tid = utracy_tid(),
		.zone_color.color = color
	});
}

UTRACY_INTERNAL UTRACY_INLINE
void utracy_emit_frame_mark(char *const name) {
	event_queue_push(&(struct event) {
		.type = UTRACY_EVT_FRAMEMARKMSG,
		.frame_mark.name = name,
		.frame_mark.timestamp = utracy_tsc()
	});
}

UTRACY_INTERNAL
long long calibrate_delay(void) {
	(void) UTRACY_MEMSET(utracy.queue.events, 0, sizeof(utracy.queue.events));

	int unsigned const iterations = (EVENT_QUEUE_CAPACITY / 2u) - 1u;

	long long clk0 = utracy_tsc();

	for(int unsigned i=0; i<iterations; i++) {
		utracy_emit_zone_begin(0);
		utracy_emit_zone_end();
	}

	long long clk1 = utracy_tsc();

	long long dclk = clk1 - clk0;

	struct event evt;
	while(0 == event_queue_pop(&evt));

	return dclk / (long long) (iterations * 2);
}

#if 0
UTRACY_INTERNAL
int utracy_write(void const *const buf, size_t size) {
	DWORD written;
	size_t offset = 0;
	while(offset < size) {
		if(FALSE == WriteFile(utracy.stream, (char *const) buf + offset, size - offset, &written, NULL)) {
			LOG_DEBUG_ERROR;
			return -1;
		}

		if(0 == written) {
			LOG_DEBUG_ERROR;
			return -1;
		}

		offset += written;
	}

	return 0;
}
#else
UTRACY_INTERNAL
int utracy_write(void const *const buf, size_t size) {
	if(utracy.fstream != NULL) fwrite(buf, 1, size, utracy.fstream);
	return 0;
}
#endif

UTRACY_INTERNAL
void utracy_flush(FILE* stream) {
	if(stream == NULL) {
		if(utracy.fstream == NULL) {
			return;
		}
		stream = utracy.fstream;
	}
	int fd = _fileno(stream);
	if(fd == -1) return;
#if defined(UTRACY_WINDOWS)
	_commit(fd);
#elif defined(UTRACY_LINUX)
	fsync(fd);
#endif
}

UTRACY_INTERNAL
int utracy_server_thread_start(void* arg) {
	event_pipe_t* profiler_connected_event = (event_pipe_t*) arg;
	
	if (profiler_connected_event) {
		set_event_pipe(profiler_connected_event);
	}

	{
		struct {
			_Alignas(8) long long unsigned signature;
			int unsigned version;
			int unsigned padding1;
			double multiplier;
			_Alignas(8) long long init_begin;
			_Alignas(8) long long init_end;
			_Alignas(8) long long delay;
			_Alignas(8) long long resolution;
			_Alignas(8) long long epoch;
			_Alignas(8) long long exec_time;
			_Alignas(8) long long pid;
			_Alignas(8) long long sampling_period;
			char unsigned flags;
			char unsigned cpu_arch;
			char cpu_manufacturer[12];
			int unsigned cpu_id;
			char program_name[64];
			char host_info[1024];
			int unsigned padding2;
		} header = {0};

		_Static_assert(sizeof(header) == 1200, "header size changed!");
		_Static_assert(sizeof(struct event) == 24, "event size changed!");

		header.signature = 0x6D64796361727475llu;
		header.version = 2;
		header.multiplier = utracy.info.multiplier;
		header.init_begin = utracy.info.init_begin;
		header.init_end = utracy.info.init_end;
		header.delay = utracy.info.delay;
		header.resolution = utracy.info.resolution;
		header.epoch = utracy.info.epoch;
		header.exec_time = utracy.info.exec_time;
		header.pid = 0;
		header.sampling_period = 0;
		header.flags = 0;
		header.cpu_arch = 0;
		(void) memcpy(header.cpu_manufacturer, "???", 3);
		header.cpu_id = 0;
		(void) memcpy(header.program_name, "dreamdaemon.exe", 15);
		(void) memcpy(header.host_info, "???", 3);

		(void) utracy_write(&header, sizeof(header));
	}

	int unsigned srclocs_len = sizeof(srclocs) / sizeof(*srclocs);
	(void) utracy_write(&srclocs_len, sizeof(srclocs_len));
	for(int unsigned i=0; i<srclocs_len; i++) {
		struct utracy_source_location srcloc = srclocs[i];

		if(NULL != srcloc.name) {
			int unsigned name_len = strlen(srcloc.name);
			(void) utracy_write(&name_len, sizeof(name_len));
			(void) utracy_write(srcloc.name, name_len);
		} else {
			int unsigned name_len = 0;
			(void) utracy_write(&name_len, sizeof(name_len));
		}

		if(NULL != srcloc.function) {
			int unsigned function_len = strlen(srcloc.function);
			(void) utracy_write(&function_len, sizeof(function_len));
			(void) utracy_write(srcloc.function, function_len);
		} else {
			int unsigned function_len = 0;
			(void) utracy_write(&function_len, sizeof(function_len));
		}

		if(NULL != srcloc.file) {
			int unsigned file_len = strlen(srcloc.file);
			(void) utracy_write(&file_len, sizeof(file_len));
			(void) utracy_write(srcloc.file, file_len);
		} else {
			int unsigned file_len = 0;
			(void) utracy_write(&file_len, sizeof(file_len));
		}

		(void) utracy_write(&srcloc.line, sizeof(srcloc.line));
		(void) utracy_write(&srcloc.color, sizeof(srcloc.color));
	}

	bool quitting = false;
	while(!quitting) {
		struct event evt;
		while(0 == event_queue_pop(&evt)) {
			(void) utracy_write(&evt, sizeof(evt));
		}
		switch (wait_for_event_pipe(utracy.quit, 1)) {
			case 0:
				quitting = true;
				break;
			case 1:
				break;
			default:
				LOG_DEBUG_ERROR;
				break;
		}
	}

	utracy_flush(NULL);
	close_event_pipe(utracy.quit);
	utracy.quit = NULL;
	return 0;
}

/* byond hooks */
UTRACY_INTERNAL
struct object UTRACY_WINDOWS_CDECL UTRACY_LINUX_REGPARM(3) exec_proc(struct proc *proc) {
	if(likely(proc->procdef < 0x14000)) {
		utracy_emit_zone_begin(proc->procdef);

		/* procs with pre-existing contexts are resuming from sleep */
		if(unlikely(proc->ctx != NULL)) {
			utracy_emit_zone_color(0xAF4444);
		}

		struct object result = byond.orig_exec_proc(proc);

		utracy_emit_zone_end();

		return result;
	}

	return byond.orig_exec_proc(proc);
}

UTRACY_INTERNAL
int UTRACY_WINDOWS_STDCALL UTRACY_LINUX_CDECL server_tick(void) {
	/* server tick is the end of a frame and the beginning of the next frame */
	utracy_emit_frame_mark(NULL);

	utracy_emit_zone_begin(0x14000);

	int interval = byond.orig_server_tick();

	utracy_emit_zone_end();

	return interval;
}

UTRACY_INTERNAL
void UTRACY_WINDOWS_CDECL UTRACY_LINUX_CDECL send_maps(void) {
	utracy_emit_zone_begin(0x14001);

	byond.orig_send_maps();

	utracy_emit_zone_end();
}

/* hooking */
UTRACY_INTERNAL
void *hook(char *const restrict dst, char *const restrict src, char unsigned size, char *trampoline) {
	char unsigned jmp[] = {
		0xE9, 0x00, 0x00, 0x00, 0x00
	};

	uintptr_t jmp_from = (uintptr_t) trampoline + size + sizeof(jmp);
	uintptr_t jmp_to = (uintptr_t) src + size;
	uintptr_t offset = jmp_to - jmp_from;
	(void) UTRACY_MEMCPY(jmp + 1, &offset, sizeof(offset));
	(void) UTRACY_MEMCPY(trampoline, src, size);
	(void) UTRACY_MEMCPY(trampoline + size, jmp, sizeof(jmp));

	jmp_from = (uintptr_t) src + sizeof(jmp);
	jmp_to = (uintptr_t) dst;
	offset = jmp_to - jmp_from;

#if defined(UTRACY_WINDOWS)
	DWORD old_protect;
	if(0 == VirtualProtect(src, size, PAGE_READWRITE, &old_protect)) {
		LOG_DEBUG_ERROR;
		return NULL;
	}

#elif defined(UTRACY_LINUX)
	if(0 != mprotect(UTRACY_ALIGN_DOWN(src, UTRACY_PAGE_SIZE), UTRACY_PAGE_SIZE, PROT_WRITE | PROT_READ)) {
		LOG_DEBUG_ERROR;
		return NULL;
	}

#endif

	(void) UTRACY_MEMCPY(jmp + 1, &offset, sizeof(offset));
	(void) UTRACY_MEMCPY(src, &jmp, sizeof(jmp));

	if(size > sizeof(jmp)) {
		for(size_t i=0; i<(size - sizeof(jmp)); i++) {
			char unsigned nop = 0x90;
			(void) UTRACY_MEMCPY(src + sizeof(jmp) + i, &nop, 1);
		}
	}

#if defined(UTRACY_WINDOWS)
	if(0 == VirtualProtect(src, size, old_protect, &old_protect)) {
		LOG_DEBUG_ERROR;
		return NULL;
	}

#elif defined(UTRACY_LINUX)
	if(0 != mprotect(UTRACY_ALIGN_DOWN(src, UTRACY_PAGE_SIZE), UTRACY_PAGE_SIZE, PROT_READ | PROT_EXEC)) {
		LOG_DEBUG_ERROR;
		return NULL;
	}

#endif

	return trampoline;
}

#if defined(UTRACY_WINDOWS)
#	define BYOND_MAX_BUILD 1660
#	define BYOND_MIN_BUILD 1543
#	define BYOND_VERSION_ADJUSTED(a) ((a) - BYOND_MIN_BUILD)

static int unsigned const byond_offsets[][11] = {
	/*                                strings     strings_len miscs       miscs_len   procdefs   procdefs_len procdef     exec_proc   server_tick send_maps   prologue */
	[BYOND_VERSION_ADJUSTED(1543)] = {0x0035FC58, 0x0035FC5C, 0x0035FC68, 0x0035FC6C, 0x0035FC78, 0x0035FC7C, 0x00180024, 0x001003B0, 0x001C7D20, 0x00187C80, 0x00050B06},
	[BYOND_VERSION_ADJUSTED(1544)] = {0x00360C58, 0x00360C5C, 0x00360C68, 0x00360C6C, 0x00360C78, 0x00360C7C, 0x00180024, 0x00100A10, 0x001C8420, 0x00188220, 0x00050B06},
	[BYOND_VERSION_ADJUSTED(1545)] = {0x00360C60, 0x00360C64, 0x00360C70, 0x00360C74, 0x00360C80, 0x00360C84, 0x00180024, 0x00100980, 0x001C8400, 0x00188190, 0x00050B06},
	[BYOND_VERSION_ADJUSTED(1546)] = {0x00360C60, 0x00360C64, 0x00360C70, 0x00360C74, 0x00360C80, 0x00360C84, 0x00180024, 0x00100830, 0x001C8280, 0x001880C0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1547)] = {0x00362C68, 0x00362C6C, 0x00362C78, 0x00362C7C, 0x00362C88, 0x00362C8C, 0x00180024, 0x00101210, 0x001C9320, 0x001891F0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1548)] = {0x00362C48, 0x00362C4C, 0x00362C58, 0x00362C5C, 0x00362C68, 0x00362C6C, 0x00180024, 0x00101640, 0x001C96D0, 0x00188E80, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1549)] = {0x00368DD4, 0x00368DD8, 0x00368DEC, 0x00368DF0, 0x00368E00, 0x00368E04, 0x00180024, 0x001023B0, 0x001CB0A0, 0x0018AD80, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1550)] = {0x0036903C, 0x00369040, 0x0036904C, 0x00369050, 0x0036905C, 0x00369060, 0x00180024, 0x00102710, 0x001CB710, 0x0018B0B0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1551)] = {0x00369034, 0x00369038, 0x00369044, 0x00369048, 0x00369054, 0x00369058, 0x00180024, 0x00102C30, 0x001CB830, 0x0018B120, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1552)] = {0x0036A054, 0x0036A058, 0x0036A064, 0x0036A068, 0x0036A074, 0x0036A078, 0x00180024, 0x00102DE0, 0x001CBDE0, 0x0018B6B0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1553)] = {0x0036E234, 0x0036E238, 0x0036E244, 0x0036E248, 0x0036E254, 0x0036E258, 0x00180024, 0x00104FF0, 0x001CF780, 0x0018DE50, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1554)] = {0x0036DFF8, 0x0036DFFC, 0x0036E008, 0x0036E00C, 0x0036E018, 0x0036E01C, 0x00180024, 0x00104ED0, 0x001CF650, 0x0018E000, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1555)] = {0x0036E0B0, 0x0036E0B4, 0x0036E0C0, 0x0036E0C4, 0x0036E0D0, 0x0036E0D4, 0x00180024, 0x001064F0, 0x001CFD80, 0x0018EEB0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1556)] = {0x0036E0AC, 0x0036E0B0, 0x0036E0BC, 0x0036E0C0, 0x0036E0CC, 0x0036E0D0, 0x00180024, 0x00106560, 0x001CFD80, 0x0018EEE0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1557)] = {0x0036E0C0, 0x0036E0C4, 0x0036E0D0, 0x0036E0D4, 0x0036E0E0, 0x0036E0E4, 0x00180024, 0x001063B0, 0x001CFB60, 0x0018EC70, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1558)] = {0x0036F4F4, 0x0036F4F8, 0x0036F504, 0x0036F508, 0x0036F514, 0x0036F518, 0x00180024, 0x00106DE0, 0x001D1160, 0x0018FD80, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1559)] = {0x0036F4F4, 0x0036F4F8, 0x0036F504, 0x0036F508, 0x0036F514, 0x0036F518, 0x00180024, 0x00106DE0, 0x001D1160, 0x0018FD80, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1560)] = {0x0036F4F4, 0x0036F4F8, 0x0036F504, 0x0036F508, 0x0036F514, 0x0036F518, 0x00180024, 0x00106AF0, 0x001D1120, 0x0018FA80, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1561)] = {0x0036F4F4, 0x0036F4F8, 0x0036F504, 0x0036F508, 0x0036F514, 0x0036F518, 0x00180024, 0x00106AF0, 0x001D1120, 0x0018FA80, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1562)] = {0x0036F538, 0x0036F53C, 0x0036F548, 0x0036F54C, 0x0036F558, 0x0036F55C, 0x00180024, 0x00106960, 0x001D0F00, 0x0018F780, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1563)] = {0x0036F538, 0x0036F53C, 0x0036F548, 0x0036F54C, 0x0036F558, 0x0036F55C, 0x00180024, 0x001066A0, 0x001D1160, 0x0018F660, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1564)] = {0x0036F538, 0x0036F53C, 0x0036F548, 0x0036F54C, 0x0036F558, 0x0036F55C, 0x00180024, 0x00106310, 0x001D0F20, 0x0018F1E0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1565)] = {0x00371538, 0x0037153C, 0x00371548, 0x0037154C, 0x00371558, 0x0037155C, 0x00180024, 0x00106960, 0x001D15A0, 0x0018FCC0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1566)] = {0x00371538, 0x0037153C, 0x00371548, 0x0037154C, 0x00371558, 0x0037155C, 0x00180024, 0x00106160, 0x001D0A70, 0x0018EF80, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1567)] = {0x00370548, 0x0037054C, 0x00370560, 0x00370564, 0x00370570, 0x00370574, 0x00180024, 0x00106220, 0x001D0B00, 0x0018F470, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1568)] = {0x00370548, 0x0037054C, 0x00370560, 0x00370564, 0x00370570, 0x00370574, 0x00180024, 0x00106220, 0x001D0B30, 0x0018F470, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1569)] = {0x00370548, 0x0037054C, 0x00370560, 0x00370564, 0x00370570, 0x00370574, 0x00180024, 0x00106220, 0x001D0B40, 0x0018F500, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1570)] = {0x00371548, 0x0037154C, 0x00371558, 0x0037155C, 0x00371568, 0x0037156C, 0x00180024, 0x00106560, 0x001D0BF0, 0x0018F8F0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1571)] = {0x00371548, 0x0037154C, 0x00371558, 0x0037155C, 0x00371568, 0x0037156C, 0x00180024, 0x001061D0, 0x001D0A70, 0x0018F500, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1572)] = {0x00371540, 0x00371544, 0x00371550, 0x00371554, 0x00371560, 0x00371564, 0x00180024, 0x001066A0, 0x001D0F60, 0x0018FCC0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1573)] = {0x00371608, 0x0037160C, 0x00371618, 0x0037161C, 0x00371628, 0x0037162C, 0x00180024, 0x00106BD0, 0x001D13C0, 0x0018FC40, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1574)] = {0x00371550, 0x00371554, 0x00371560, 0x00371564, 0x00371570, 0x00371574, 0x00180024, 0x001065A0, 0x001D10E0, 0x0018FDC0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1575)] = {0x00371550, 0x00371554, 0x00371560, 0x00371564, 0x00371570, 0x00371574, 0x00180024, 0x001065A0, 0x001D10E0, 0x0018FDC0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1576)] = {0x003745BC, 0x003745C0, 0x003745CC, 0x003745D0, 0x003745DC, 0x003745E0, 0x00180024, 0x001087B0, 0x001D30A0, 0x00191C60, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1577)] = {0x003745BC, 0x003745C0, 0x003745CC, 0x003745D0, 0x003745DC, 0x003745E0, 0x00180024, 0x00107FC0, 0x001D2C90, 0x00191A60, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1578)] = {0x003745BC, 0x003745C0, 0x003745CC, 0x003745D0, 0x003745DC, 0x003745E0, 0x00180024, 0x001083B0, 0x001D2E90, 0x00191910, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1579)] = {0x003745C8, 0x003745CC, 0x003745D8, 0x003745DC, 0x003745E8, 0x003745EC, 0x00180024, 0x00108C20, 0x001D3940, 0x001925C0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1580)] = {0x003745C8, 0x003745CC, 0x003745D8, 0x003745DC, 0x003745E8, 0x003745EC, 0x00180024, 0x00108BD0, 0x001D38B0, 0x00192520, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1581)] = {0x003745C8, 0x003745CC, 0x003745D8, 0x003745DC, 0x003745E8, 0x003745EC, 0x00180024, 0x001086A0, 0x001D3780, 0x001923A0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1582)] = {0x003745C8, 0x003745CC, 0x003745D8, 0x003745DC, 0x003745E8, 0x003745EC, 0x00180024, 0x001087B0, 0x001D3A40, 0x00191FF0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1583)] = {0x003755C8, 0x003755CC, 0x003755D8, 0x003755DC, 0x003755E8, 0x003755EC, 0x00180024, 0x00108240, 0x001D33F0, 0x001919E0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1584)] = {0x003764B4, 0x003764B8, 0x003764C4, 0x003764C8, 0x003764D4, 0x003764D8, 0x00180024, 0x00108460, 0x001D3A40, 0x001922C0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1585)] = {0x003774AC, 0x003774B0, 0x003774BC, 0x003774C0, 0x003774CC, 0x003774D0, 0x00180024, 0x001094D0, 0x001D49E0, 0x00192D80, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1586)] = {0x00378524, 0x00378528, 0x00378534, 0x00378538, 0x00378544, 0x00378548, 0x00180024, 0x00109AA0, 0x001D5160, 0x00193370, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1587)] = {0x00378524, 0x00378528, 0x00378534, 0x00378538, 0x00378544, 0x00378548, 0x00180024, 0x00109AA0, 0x001D5160, 0x00193370, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1588)] = {0x00378524, 0x00378528, 0x00378534, 0x00378538, 0x00378544, 0x00378548, 0x00180024, 0x00109B10, 0x001D5220, 0x00193840, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1589)] = {0x00378524, 0x00378528, 0x00378534, 0x00378538, 0x00378544, 0x00378548, 0x00180024, 0x00109AA0, 0x001D5190, 0x00193710, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1590)] = {0x00396974, 0x00396978, 0x00396984, 0x00396988, 0x00396994, 0x00396998, 0x00180024, 0x00118180, 0x001EA800, 0x001A6A80, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1591)] = {0x00396974, 0x00396978, 0x00396984, 0x00396988, 0x00396994, 0x00396998, 0x00180024, 0x001175E0, 0x001E9F00, 0x001A5F00, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1592)] = {0x00396974, 0x00396978, 0x00396984, 0x00396988, 0x00396994, 0x00396998, 0x00180024, 0x00117890, 0x001EA900, 0x001A6380, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1593)] = {0x00396974, 0x00396978, 0x00396984, 0x00396988, 0x00396994, 0x00396998, 0x00180024, 0x00118090, 0x001EAB30, 0x001A6920, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1594)] = {0x00397B6C, 0x00397B70, 0x00397B7C, 0x00397B80, 0x00397B8C, 0x00397B90, 0x00180024, 0x00118590, 0x001EBBB0, 0x001A8140, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1595)] = {0x0039AB58, 0x0039AB5C, 0x0039AB68, 0x0039AB6C, 0x0039AB78, 0x0039AB7C, 0x00180024, 0x0011A810, 0x001EED90, 0x001AB310, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1596)] = {0x0039AB58, 0x0039AB5C, 0x0039AB68, 0x0039AB6C, 0x0039AB78, 0x0039AB7C, 0x00180024, 0x0011A090, 0x001EE950, 0x001AAC20, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1597)] = {0x0039CB74, 0x0039CB78, 0x0039CB84, 0x0039CB88, 0x0039CB94, 0x0039CB98, 0x00180024, 0x0011B5A0, 0x001EF8A0, 0x001AC2A0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1598)] = {0x0039EBC8, 0x0039EBCC, 0x0039EBD8, 0x0039EBDC, 0x0039EBE8, 0x0039EBEC, 0x00180024, 0x0011BF40, 0x001F0B40, 0x001ACFF0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1599)] = {0x0039EBC8, 0x0039EBCC, 0x0039EBD8, 0x0039EBDC, 0x0039EBE8, 0x0039EBEC, 0x00180024, 0x0011B640, 0x001F0910, 0x001AC9B0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1600)] = {0x0039EBC8, 0x0039EBCC, 0x0039EBD8, 0x0039EBDC, 0x0039EBE8, 0x0039EBEC, 0x00180024, 0x0011BE70, 0x001F08B0, 0x001AD170, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1601)] = {0x0039FC0C, 0x0039FC10, 0x0039FC1C, 0x0039FC20, 0x0039FC2C, 0x0039FC30, 0x00180024, 0x0011BC70, 0x001F0DC0, 0x001ACAA0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1602)] = {0x003A2C50, 0x003A2C58, 0x003A2C68, 0x003A2C6C, 0x003A2C78, 0x003A2C7C, 0x00180024, 0x0011EB80, 0x001F3350, 0x001AF9F0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1603)] = {0x003A3DE0, 0x003A3DE8, 0x003A3DF8, 0x003A3DFC, 0x003A3E08, 0x003A3E0C, 0x00180024, 0x0011EC00, 0x001F3890, 0x001AFB90, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1604)] = {0x003A1D88, 0x003A1D8C, 0x003A1D98, 0x003A1D9C, 0x003A1DA8, 0x003A1DAC, 0x00180024, 0x0011E570, 0x001F3A50, 0x001AF6D0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1605)] = {0x003A2D80, 0x003A2D84, 0x003A2D90, 0x003A2D94, 0x003A2DA0, 0x003A2DA4, 0x00180024, 0x0011E250, 0x001F3A20, 0x001AFAC0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1606)] = {0x003A2D80, 0x003A2D84, 0x003A2D90, 0x003A2D94, 0x003A2DA0, 0x003A2DA4, 0x00180024, 0x0011E230, 0x001F39C0, 0x001AFA50, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1607)] = {0x003A3DE0, 0x003A3DE4, 0x003A3DF0, 0x003A3DF4, 0x003A3E00, 0x003A3E04, 0x00180024, 0x0011EF00, 0x001F48B0, 0x001B0560, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1608)] = {0x003A3DE0, 0x003A3DE4, 0x003A3DF0, 0x003A3DF4, 0x003A3E00, 0x003A3E04, 0x00180024, 0x0011ED70, 0x001F4B30, 0x001B0680, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1609)] = {0x003AB1E8, 0x003AB1EC, 0x003AB1F8, 0x003AB1FC, 0x003AB208, 0x003AB20C, 0x00180024, 0x0011FE90, 0x001F5900, 0x001B14D0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1610)] = {0x003AA23C, 0x003AA240, 0x003AA24C, 0x003AA250, 0x003AA25C, 0x003AA260, 0x00180024, 0x0011F670, 0x001F5C30, 0x001B1450, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1611)] = {0x003AD3A8, 0x003AD3AC, 0x003AD3B8, 0x003AD3BC, 0x003AD3C8, 0x003AD3CC, 0x00180024, 0x0011F220, 0x001F5950, 0x001B0D10, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1612)] = {0x003AD3A8, 0x003AD3AC, 0x003AD3B8, 0x003AD3BC, 0x003AD3C8, 0x003AD3CC, 0x00180024, 0x0011F220, 0x001F58F0, 0x001B0C90, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1613)] = {0x003AD3A8, 0x003AD3AC, 0x003AD3B8, 0x003AD3BC, 0x003AD3C8, 0x003AD3CC, 0x00180024, 0x0011F3C0, 0x001F59E0, 0x001B0F20, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1614)] = {0x003AC3A8, 0x003AC3AC, 0x003AC3B8, 0x003AC3BC, 0x003AC3C8, 0x003AC3CC, 0x00180024, 0x0011EBE0, 0x001F50E0, 0x001B0A50, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1615)] = {0x004073E0, 0x004073E4, 0x004073F0, 0x004073F4, 0x00407400, 0x00407404, 0x00180024, 0x00130F20, 0x0020B580, 0x001C3AD0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1616)] = {0x004073E0, 0x004073E4, 0x004073F0, 0x004073F4, 0x00407400, 0x00407404, 0x00180024, 0x00131210, 0x0020B9E0, 0x001C3E20, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1617)] = {0x004074B0, 0x004074B4, 0x004074C0, 0x004074C4, 0x004074D0, 0x004074D4, 0x00180028, 0x001312D0, 0x0020BAB0, 0x001C3EB0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1618)] = {0x004074B0, 0x004074B4, 0x004074C0, 0x004074C4, 0x004074D0, 0x004074D4, 0x00180028, 0x00131350, 0x0020BBA0, 0x001C3F40, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1619)] = {0x004074B0, 0x004074B4, 0x004074C0, 0x004074C4, 0x004074D0, 0x004074D4, 0x00180028, 0x00131350, 0x0020BBA0, 0x001C3F40, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1620)] = {0x0040758C, 0x00407590, 0x0040759C, 0x004075A0, 0x004075AC, 0x004075B0, 0x00180028, 0x001313C0, 0x0020BC00, 0x001C3F60, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1621)] = {0x0040758C, 0x00407590, 0x0040759C, 0x004075A0, 0x004075AC, 0x004075B0, 0x00180028, 0x001313B0, 0x0020BC70, 0x001C3FC0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1622)] = {0x0040755C, 0x00407560, 0x0040756C, 0x00407570, 0x0040757C, 0x00407580, 0x00180028, 0x001312D0, 0x0020BB90, 0x001C3EB0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1623)] = {0x0040755C, 0x00407560, 0x0040756C, 0x00407570, 0x0040757C, 0x00407580, 0x00180028, 0x001312D0, 0x0020BB90, 0x001C3EB0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1624)] = {0x00407564, 0x00407568, 0x00407574, 0x00407578, 0x00407584, 0x00407588, 0x001C002C, 0x00130D40, 0x0020B810, 0x001C3940, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1625)] = {0x00407564, 0x00407568, 0x00407574, 0x00407578, 0x00407584, 0x00407588, 0x001C002C, 0x00130D40, 0x0020B810, 0x001C3940, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1626)] = {0x00407564, 0x00407568, 0x00407574, 0x00407578, 0x00407584, 0x00407588, 0x001C002C, 0x00130CF0, 0x0020B780, 0x001C38C0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1627)] = {0x0040556C, 0x00405570, 0x0040557C, 0x00405580, 0x0040558C, 0x00405590, 0x001C002C, 0x0012F570, 0x0020A030, 0x001C2140, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1630)] = {0x0040556C, 0x00405570, 0x0040557C, 0x00405580, 0x0040558C, 0x00405590, 0x001C002C, 0x0012F710, 0x0020A2E0, 0x001C2430, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1631)] = {0x0040756C, 0x00407570, 0x0040757C, 0x00407580, 0x0040758C, 0x00407590, 0x001C002C, 0x0012FB30, 0x0020A830, 0x001C2970, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1632)] = {0x0040756C, 0x00407570, 0x0040757C, 0x00407580, 0x0040758C, 0x00407590, 0x001C002C, 0x0012FC00, 0x0020A8D0, 0x001C29D0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1633)] = {0x00407574, 0x00407578, 0x00407584, 0x00407588, 0x00407594, 0x00407598, 0x001C002C, 0x0012FCF0, 0x0020A9D0, 0x001C2AE0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1634)] = {0x00408574, 0x00408578, 0x00408584, 0x00408588, 0x00408594, 0x00408598, 0x001C002C, 0x0012FCF0, 0x0020A9D0, 0x001C2AE0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1635)] = {0x00408574, 0x00408578, 0x00408584, 0x00408588, 0x00408594, 0x00408598, 0x001C002C, 0x0012FE00, 0x0020AAD0, 0x001C2BD0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1636)] = {0x0040860C, 0x00408610, 0x0040861C, 0x00408620, 0x0040862C, 0x00408630, 0x001C002C, 0x0012FFE0, 0x0020AEE0, 0x001C2F60, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1637)] = {0x0040860C, 0x00408610, 0x0040861C, 0x00408620, 0x0040862C, 0x00408630, 0x001C002C, 0x00130290, 0x0020B290, 0x001C3270, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1638)] = {0x0040960C, 0x00409610, 0x0040961C, 0x00409620, 0x0040962C, 0x00409630, 0x001C002C, 0x00130AE0, 0x0020BB10, 0x001C3AE0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1639)] = {0x0040960C, 0x00409610, 0x0040961C, 0x00409620, 0x0040962C, 0x00409630, 0x001C002C, 0x00130AE0, 0x0020BB10, 0x001C3AE0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1640)] = {0x0040960C, 0x00409610, 0x0040961C, 0x00409620, 0x0040962C, 0x00409630, 0x001C002C, 0x00130AA0, 0x0020BB40, 0x001C3AE0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1641)] = {0x00409614, 0x00409618, 0x00409624, 0x00409628, 0x00409634, 0x00409638, 0x001C002C, 0x00130B20, 0x0020BA10, 0x001C3890, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1642)] = {0x00409614, 0x00409618, 0x00409624, 0x00409628, 0x00409634, 0x00409638, 0x001C002C, 0x00130B20, 0x0020BAE0, 0x001C3940, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1643)] = {0x0040961C, 0x00409620, 0x0040962C, 0x00409630, 0x0040963C, 0x00409640, 0x001C002C, 0x00130B20, 0x0020BAD0, 0x001C38E0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1644)] = {0x004096BC, 0x004096C0, 0x004096CC, 0x004096D0, 0x004096DC, 0x004096E0, 0x001C002C, 0x00130D60, 0x0020BD20, 0x001C3B90, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1645)] = {0x0040A6C4, 0x0040A6C8, 0x0040A6D4, 0x0040A6D8, 0x0040A6E4, 0x0040A6E8, 0x001C002C, 0x00131240, 0x0020C260, 0x001C4060, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1646)] = {0x0040A6C4, 0x0040A6C8, 0x0040A6D4, 0x0040A6D8, 0x0040A6E4, 0x0040A6E8, 0x001C002C, 0x00131310, 0x0020C300, 0x001C4160, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1647)] = {0x0040A6C4, 0x0040A6C8, 0x0040A6D4, 0x0040A6D8, 0x0040A6E4, 0x0040A6E8, 0x001C002C, 0x00131260, 0x0020c430, 0x001C4250, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1648)] = {0x00424978, 0x0042497C, 0x00424988, 0x0042498C, 0x00424998, 0x0042499C, 0x001C002C, 0x0013A660, 0x00223A60, 0x001D5DD0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1649)] = {0x00424998, 0x0042499C, 0x004249A8, 0x004249AC, 0x004249B8, 0x004249BC, 0x001C002C, 0x0013A850, 0x00223E90, 0x001D61C0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1650)] = {0x00425998, 0x0042599C, 0x004259A8, 0x004259AC, 0x004259B8, 0x004259BC, 0x001C002C, 0x0013A9D0, 0x002242A0, 0x001D6500, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1651)] = {0x00426998, 0x0042699C, 0x004269A8, 0x004269AC, 0x004269B8, 0x004269BC, 0x001C002C, 0x0013AB10, 0x002243F0, 0x001D6650, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1652)] = {0x00426998, 0x0042699C, 0x004269A8, 0x004269AC, 0x004269B8, 0x004269BC, 0x001C002C, 0x0013AE10, 0x002247D0, 0x001D69E0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1653)] = {0x004269A4, 0x004269A8, 0x004269B4, 0x004269B8, 0x004269C4, 0x004269C8, 0x001C002C, 0x0013B0E0, 0x00224B10, 0x001D6CB0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1654)] = {0x004269A4, 0x004269A8, 0x004269B4, 0x004269B8, 0x004269C4, 0x004269C8, 0x001C002C, 0x0013B0E0, 0x00224B10, 0x001D6CB0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1655)] = {0x004269A4, 0x004269A8, 0x004269B4, 0x004269B8, 0x004269C4, 0x004269C8, 0x001C002C, 0x0013B140, 0x00224C40, 0x001D6D10, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1656)] = {0x004279B4, 0x004279B8, 0x004279C4, 0x004279C8, 0x004279D4, 0x004279D8, 0x001C002C, 0x0013B580, 0x00224FF0, 0x001D7130, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1657)] = {0x004279B4, 0x004279B8, 0x004279C4, 0x004279C8, 0x004279D4, 0x004279D8, 0x001C002C, 0x0013B760, 0x00225230, 0x001D7320, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1658)] = {0x004279B4, 0x004279B8, 0x004279C4, 0x004279C8, 0x004279D4, 0x004279D8, 0x001C002C, 0x0013B7F0, 0x002252B0, 0x001D73B0, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1659)] = {0x004279B4, 0x004279B8, 0x004279C4, 0x004279C8, 0x004279D4, 0x004279D8, 0x001C002C, 0x0013B8A0, 0x002254D0, 0x001D7460, 0x00050606},
	[BYOND_VERSION_ADJUSTED(1660)] = {0x004289B4, 0x004289B8, 0x004289C4, 0x004289C8, 0x004289D4, 0x004289D8, 0x001C002C, 0x0013B8A0, 0x00225A60, 0x001D79A0, 0x00050606},
};

#elif defined(UTRACY_LINUX)
#	define BYOND_MAX_BUILD 1660
#	define BYOND_MIN_BUILD 1543
#	define BYOND_VERSION_ADJUSTED(a) ((a) - BYOND_MIN_BUILD)

static int unsigned const byond_offsets[][11] = {
	/*                                strings     strings_len miscs       miscs_len   procdefs   procdefs_len procdef     exec_proc   server_tick send_maps   prologue */
	[BYOND_VERSION_ADJUSTED(1543)] = {0x0063F9B8, 0x0063F9BC, 0x0063F9D0, 0x0063F9D4, 0x0063FA0C, 0x0063FA10, 0x00180024, 0x002E31E0, 0x002B7710, 0x002B28D0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1544)] = {0x00640BB8, 0x00640BBC, 0x00640BD0, 0x00640BD4, 0x00640C0C, 0x00640C10, 0x00180024, 0x002E3A60, 0x002B7F90, 0x002B3150, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1545)] = {0x006409D8, 0x006409DC, 0x006409F0, 0x006409F4, 0x00640A2C, 0x00640A30, 0x00180024, 0x002E3D00, 0x002B8230, 0x002B33F0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1546)] = {0x006409D8, 0x006409DC, 0x006409F0, 0x006409F4, 0x00640A2C, 0x00640A30, 0x00180024, 0x002E3ED0, 0x002B83F0, 0x002B3570, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1547)] = {0x00642A38, 0x00642A3C, 0x00642A50, 0x00642A54, 0x00642A8C, 0x00642A90, 0x00180024, 0x002E4D30, 0x002B8F40, 0x002B4320, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1548)] = {0x00643A38, 0x00643A3C, 0x00643A50, 0x00643A54, 0x00643A8C, 0x00643A90, 0x00180024, 0x002E5CB0, 0x002B9ED0, 0x002B52B0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1549)] = {0x006459D8, 0x006459DC, 0x006459F0, 0x006459F4, 0x00645A2C, 0x00645A30, 0x00180024, 0x002E6C30, 0x002BADD0, 0x002B5F10, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1550)] = {0x006469D8, 0x006469DC, 0x006469F0, 0x006469F4, 0x00646A2C, 0x00646A30, 0x00180024, 0x002E7B80, 0x002BB910, 0x002B6A50, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1551)] = {0x006469D8, 0x006469DC, 0x006469F0, 0x006469F4, 0x00646A2C, 0x00646A30, 0x00180024, 0x002E77C0, 0x002BB520, 0x002B6660, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1552)] = {0x006469D8, 0x006469DC, 0x006469F0, 0x006469F4, 0x00646A2C, 0x00646A30, 0x00180024, 0x002E7D20, 0x002BBA70, 0x002B6BB0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1553)] = {0x00651B18, 0x00651B1C, 0x00651B30, 0x00651B34, 0x00651B6C, 0x00651B70, 0x00180024, 0x002F1490, 0x002C51E0, 0x002BCE30, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1554)] = {0x00651B18, 0x00651B1C, 0x00651B30, 0x00651B34, 0x00651B6C, 0x00651B70, 0x00180024, 0x002F1D10, 0x002C5280, 0x002BCED0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1555)] = {0x00653B28, 0x00653B2C, 0x00653B40, 0x00653B44, 0x00653B8C, 0x00653B90, 0x00180024, 0x002F2EA0, 0x002C5F90, 0x002BE1A0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1556)] = {0x00653B28, 0x00653B2C, 0x00653B40, 0x00653B44, 0x00653B8C, 0x00653B90, 0x00180024, 0x002F2BE0, 0x002C5CD0, 0x002BDEE0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1557)] = {0x00653B28, 0x00653B2C, 0x00653B40, 0x00653B44, 0x00653B8C, 0x00653B90, 0x00180024, 0x002F2A40, 0x002C5B40, 0x002BDD50, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1558)] = {0x00656B48, 0x00656B4C, 0x00656B60, 0x00656B64, 0x00656BAC, 0x00656BB0, 0x00180024, 0x002F5020, 0x002C8070, 0x002C0280, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1559)] = {0x00656B48, 0x00656B4C, 0x00656B60, 0x00656B64, 0x00656BAC, 0x00656BB0, 0x00180024, 0x002F5020, 0x002C8070, 0x002C0280, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1560)] = {0x00656B48, 0x00656B4C, 0x00656B60, 0x00656B64, 0x00656BAC, 0x00656BB0, 0x00180024, 0x002F5040, 0x002C8090, 0x002C02A0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1562)] = {0x0065AB48, 0x0065AB4C, 0x0065AB60, 0x0065AB64, 0x0065ABAC, 0x0065ABB0, 0x00180024, 0x002F89B0, 0x002CBA20, 0x002C3C30, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1563)] = {0x0065ABC8, 0x0065ABCC, 0x0065ABE0, 0x0065ABE4, 0x0065AC2C, 0x0065AC30, 0x00180024, 0x002F87E0, 0x002CB850, 0x002C3A60, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1564)] = {0x00659B48, 0x00659B4C, 0x00659B60, 0x00659B64, 0x00659BAC, 0x00659BB0, 0x00180024, 0x002F8680, 0x002CB6F0, 0x002C3900, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1565)] = {0x0065FB48, 0x0065FB4C, 0x0065FB60, 0x0065FB64, 0x0065FBAC, 0x0065FBB0, 0x00180024, 0x002F9990, 0x002CCA00, 0x002C4C10, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1566)] = {0x0065EB48, 0x0065EB4C, 0x0065EB60, 0x0065EB64, 0x0065EBAC, 0x0065EBB0, 0x00180024, 0x002F8830, 0x002CB8A0, 0x002C3AB0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1567)] = {0x0065CB48, 0x0065CB4C, 0x0065CB60, 0x0065CB64, 0x0065CBAC, 0x0065CBB0, 0x00180024, 0x002F74D0, 0x002CA480, 0x002C2690, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1568)] = {0x0065CB48, 0x0065CB4C, 0x0065CB60, 0x0065CB64, 0x0065CBAC, 0x0065CBB0, 0x00180024, 0x002F74D0, 0x002CA480, 0x002C2690, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1569)] = {0x0065CB48, 0x0065CB4C, 0x0065CB60, 0x0065CB64, 0x0065CBAC, 0x0065CBB0, 0x00180024, 0x002F74C0, 0x002CA470, 0x002C2680, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1570)] = {0x0065CB48, 0x0065CB4C, 0x0065CB60, 0x0065CB64, 0x0065CBAC, 0x0065CBB0, 0x00180024, 0x002F78E0, 0x002CA870, 0x002C2A90, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1571)] = {0x0065CB48, 0x0065CB4C, 0x0065CB60, 0x0065CB64, 0x0065CBAC, 0x0065CBB0, 0x00180024, 0x002F7900, 0x002CA890, 0x002C2AB0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1572)] = {0x0065DB48, 0x0065DB4C, 0x0065DB60, 0x0065DB64, 0x0065DBAC, 0x0065DBB0, 0x00180024, 0x002F8110, 0x002CB0A0, 0x002C32C0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1573)] = {0x0065DC28, 0x0065DC2C, 0x0065DC40, 0x0065DC44, 0x0065DC8C, 0x0065DC90, 0x00180024, 0x002F7EE0, 0x002CAE70, 0x002C3090, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1574)] = {0x0065DB68, 0x0065DB6C, 0x0065DB80, 0x0065DB84, 0x0065DBCC, 0x0065DBD0, 0x00180024, 0x002F8280, 0x002CB210, 0x002C3430, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1575)] = {0x0065DB68, 0x0065DB6C, 0x0065DB80, 0x0065DB84, 0x0065DBCC, 0x0065DBD0, 0x00180024, 0x002F8280, 0x002CB210, 0x002C3430, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1576)] = {0x00664BC8, 0x00664BCC, 0x00664BE0, 0x00664BE4, 0x00664C2C, 0x00664C30, 0x00180024, 0x002FCFC0, 0x002CFF50, 0x002C8170, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1577)] = {0x00664BC8, 0x00664BCC, 0x00664BE0, 0x00664BE4, 0x00664C2C, 0x00664C30, 0x00180024, 0x002FCFD0, 0x002CFF60, 0x002C8180, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1578)] = {0x00664D08, 0x00664D0C, 0x00664D20, 0x00664D24, 0x00664D6C, 0x00664D70, 0x00180024, 0x002FC5D0, 0x002CF550, 0x002C7770, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1579)] = {0x00664BCC, 0x00664BD0, 0x00664BE4, 0x00664BE8, 0x00664C2C, 0x00664C30, 0x00180024, 0x002FC740, 0x002CF590, 0x002C77B0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1580)] = {0x00664BCC, 0x00664BD0, 0x00664BE4, 0x00664BE8, 0x00664C2C, 0x00664C30, 0x00180024, 0x002FC760, 0x002CF5A0, 0x002C77C0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1581)] = {0x00664BCC, 0x00664BD0, 0x00664BE4, 0x00664BE8, 0x00664C2C, 0x00664C30, 0x00180024, 0x002FC740, 0x002CF580, 0x002C77A0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1582)] = {0x00666C2C, 0x00666C30, 0x00666C44, 0x00666C48, 0x00666C8C, 0x00666C90, 0x00180024, 0x002FCEF0, 0x002CFBE0, 0x002C7E00, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1583)] = {0x00666BCC, 0x00666BD0, 0x00666BE4, 0x00666BE8, 0x00666C2C, 0x00666C30, 0x00180024, 0x002FCEF0, 0x002CFBE0, 0x002C7E00, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1584)] = {0x00668BCC, 0x00668BD0, 0x00668BE4, 0x00668BE8, 0x00668C2C, 0x00668C30, 0x00180024, 0x002FD510, 0x002D0200, 0x002C85D0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1585)] = {0x0066BBEC, 0x0066BBF0, 0x0066BC04, 0x0066BC08, 0x0066BC4C, 0x0066BC50, 0x00180024, 0x00300350, 0x002D2E90, 0x002CB2B0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1586)] = {0x0066FC0C, 0x0066FC10, 0x0066FC24, 0x0066FC28, 0x0066FC6C, 0x0066FC70, 0x00180024, 0x00303C40, 0x002D6770, 0x002CE3D0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1587)] = {0x0066FC0C, 0x0066FC10, 0x0066FC24, 0x0066FC28, 0x0066FC6C, 0x0066FC70, 0x00180024, 0x00303CF0, 0x002D6820, 0x002CE480, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1588)] = {0x0066FC0C, 0x0066FC10, 0x0066FC24, 0x0066FC28, 0x0066FC6C, 0x0066FC70, 0x00180024, 0x00303CC0, 0x002D67F0, 0x002CE450, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1589)] = {0x00671C0C, 0x00671C10, 0x00671C24, 0x00671C28, 0x00671C6C, 0x00671C70, 0x00180024, 0x00305550, 0x002D80A0, 0x002CFD50, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1590)] = {0x006B15E8, 0x006B15EC, 0x006B1600, 0x006B1604, 0x006B164C, 0x006B1650, 0x00180024, 0x00313220, 0x002FFBA0, 0x002F5DA0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1591)] = {0x006B17C8, 0x006B17CC, 0x006B17E0, 0x006B17E4, 0x006B182C, 0x006B1830, 0x00180024, 0x00313440, 0x002FFDC0, 0x002F5DC0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1592)] = {0x006B19C8, 0x006B19CC, 0x006B19E0, 0x006B19E4, 0x006B1A2C, 0x006B1A30, 0x00180024, 0x003135F0, 0x002FFF70, 0x002F5F70, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1593)] = {0x006B1C68, 0x006B1C6C, 0x006B1C80, 0x006B1C84, 0x006B1CCC, 0x006B1CD0, 0x00180024, 0x00313820, 0x003001A0, 0x002F61A0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1594)] = {0x006B7C68, 0x006B7C6C, 0x006B7C80, 0x006B7C84, 0x006B7CCC, 0x006B7CD0, 0x00180024, 0x003172C0, 0x00303B80, 0x002F9C40, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1595)] = {0x006BA7A8, 0x006BA7AC, 0x006BA7C0, 0x006BA7C4, 0x006BA80C, 0x006BA810, 0x00180024, 0x003163B0, 0x00303400, 0x002F94C0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1596)] = {0x006BB348, 0x006BB34C, 0x006BB360, 0x006BB364, 0x006BB3AC, 0x006BB3B0, 0x00180024, 0x00316D60, 0x00303F80, 0x002FA040, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1597)] = {0x006BC068, 0x006BC06C, 0x006BC080, 0x006BC084, 0x006BC0CC, 0x006BC0D0, 0x00180024, 0x003188A0, 0x00305AC0, 0x002FBB80, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1598)] = {0x006C4288, 0x006C428C, 0x006C42A0, 0x006C42A4, 0x006C42EC, 0x006C42F0, 0x00180024, 0x0031B540, 0x003077D0, 0x002FD810, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1599)] = {0x006C3AE8, 0x006C3AEC, 0x006C3B00, 0x006C3B04, 0x006C3B4C, 0x006C3B50, 0x00180024, 0x0031B0A0, 0x00307330, 0x002FD370, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1600)] = {0x006C38A8, 0x006C38AC, 0x006C38C0, 0x006C38C4, 0x006C390C, 0x006C3910, 0x00180024, 0x0031AE30, 0x003070C0, 0x002FD100, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1601)] = {0x006C5B48, 0x006C5B4C, 0x006C5B60, 0x006C5B64, 0x006C5BAC, 0x006C5BB0, 0x00180024, 0x0031B790, 0x00307A80, 0x002FD9A0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1602)] = {0x006CD928, 0x006CD92C, 0x006CD940, 0x006CD944, 0x006CD98C, 0x006CD990, 0x00180024, 0x00322000, 0x0030E300, 0x003041E0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1603)] = {0x006CF7A8, 0x006CF7AC, 0x006CF7C0, 0x006CF7C4, 0x006CF80C, 0x006CF810, 0x00180024, 0x00321F50, 0x0030E260, 0x003042A0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1604)] = {0x006CD4E8, 0x006CD4EC, 0x006CD500, 0x006CD504, 0x006CD54C, 0x006CD550, 0x00180024, 0x00321CC0, 0x0030DF60, 0x00304550, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1605)] = {0x006CD868, 0x006CD86C, 0x006CD880, 0x006CD884, 0x006CD8CC, 0x006CD8D0, 0x00180024, 0x00321F10, 0x0030E130, 0x00306750, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1606)] = {0x006CD8C8, 0x006CD8CC, 0x006CD8E0, 0x006CD8E4, 0x006CD92C, 0x006CD930, 0x00180024, 0x00321F30, 0x0030E150, 0x00306770, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1607)] = {0x006CA928, 0x006CA92C, 0x006CA940, 0x006CA944, 0x006CA98C, 0x006CA990, 0x00180024, 0x0031F170, 0x0030B370, 0x00303970, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1608)] = {0x006CA628, 0x006CA62C, 0x006CA640, 0x006CA644, 0x006CA68C, 0x006CA690, 0x00180024, 0x0031EF70, 0x0030B170, 0x00303770, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1609)] = {0x006DFB88, 0x006DFB8C, 0x006DFBA0, 0x006DFBA4, 0x006DFBEC, 0x006DFBF0, 0x00180024, 0x00326A20, 0x00312B20, 0x0030A810, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1610)] = {0x006DE428, 0x006DE42C, 0x006DE440, 0x006DE444, 0x006DE48C, 0x006DE490, 0x00180024, 0x00325850, 0x00311790, 0x003093D0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1611)] = {0x006D69E8, 0x006D69EC, 0x006D6A00, 0x006D6A04, 0x006D6A4C, 0x006D6A50, 0x00180024, 0x00322AA0, 0x0030FA20, 0x00307660, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1613)] = {0x006D6C48, 0x006D6C4C, 0x006D6C60, 0x006D6C64, 0x006D6CAC, 0x006D6CB0, 0x00180024, 0x00322CD0, 0x0030FC50, 0x00307890, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1614)] = {0x006D62C8, 0x006D62CC, 0x006D62E0, 0x006D62E4, 0x006D632C, 0x006D6330, 0x00180024, 0x00323550, 0x003104B0, 0x003080F0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1615)] = {0x006D83E8, 0x006D83EC, 0x006D8400, 0x006D8404, 0x006D844C, 0x006D8450, 0x00180024, 0x00324FF0, 0x00311F50, 0x00309B90, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1616)] = {0x006D8608, 0x006D860C, 0x006D8620, 0x006D8624, 0x006D866C, 0x006D8670, 0x00180024, 0x00325190, 0x003120F0, 0x00309D30, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1617)] = {0x006DA978, 0x006DA97C, 0x006DA990, 0x006DA994, 0x006DA9CC, 0x006DA9D0, 0x00180028, 0x00326510, 0x00313430, 0x0030B070, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1618)] = {0x006DA6D8, 0x006DA6DC, 0x006DA6F0, 0x006DA6F4, 0x006DA72C, 0x006DA730, 0x00180028, 0x00326250, 0x00313170, 0x0030ADB0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1619)] = {0x006DA698, 0x006DA69C, 0x006DA6B0, 0x006DA6B4, 0x006DA6EC, 0x006DA6F0, 0x00180028, 0x00326240, 0x00313160, 0x0030ADA0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1620)] = {0x006D61D8, 0x006D61DC, 0x006D61F0, 0x006D61F4, 0x006D622C, 0x006D6230, 0x00180028, 0x00324BE0, 0x00311AE0, 0x00309720, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1621)] = {0x006D8698, 0x006D869C, 0x006D86B0, 0x006D86B4, 0x006D86EC, 0x006D86F0, 0x00180028, 0x003252F0, 0x003121F0, 0x00309E30, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1622)] = {0x006D71B8, 0x006D71BC, 0x006D71D0, 0x006D71D4, 0x006D720C, 0x006D7210, 0x00180028, 0x00324BC0, 0x00311AC0, 0x00309700, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1623)] = {0x006D71B8, 0x006D71BC, 0x006D71D0, 0x006D71D4, 0x006D720C, 0x006D7210, 0x00180028, 0x00324BD0, 0x00311AD0, 0x00309710, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1624)] = {0x006D6198, 0x006D619C, 0x006D61B0, 0x006D61B4, 0x006D61EC, 0x006D61F0, 0x001C002C, 0x00323E00, 0x00310C60, 0x003088A0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1625)] = {0x006D6198, 0x006D619C, 0x006D61B0, 0x006D61B4, 0x006D61EC, 0x006D61F0, 0x001C002C, 0x00323E20, 0x00310C80, 0x003088C0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1626)] = {0x006D6198, 0x006D619C, 0x006D61B0, 0x006D61B4, 0x006D61EC, 0x006D61F0, 0x001C002C, 0x00323BC0, 0x00310A20, 0x00308660, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1627)] = {0x006D3198, 0x006D319C, 0x006D31B0, 0x006D31B4, 0x006D31EC, 0x006D31F0, 0x001C002C, 0x00320D10, 0x0030DB70, 0x003057B0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1630)] = {0x006D47B8, 0x006D47BC, 0x006D47D0, 0x006D47D4, 0x006D480C, 0x006D4810, 0x001C002C, 0x003213E0, 0x0030E240, 0x00305E80, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1631)] = {0x006D84D8, 0x006D84DC, 0x006D84F0, 0x006D84F4, 0x006D852C, 0x006D8530, 0x001C002C, 0x00322120, 0x0030EF80, 0x00306BC0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1632)] = {0x006D85F8, 0x006D85FC, 0x006D8610, 0x006D8614, 0x006D864C, 0x006D8650, 0x001C002C, 0x00322140, 0x0030EFA0, 0x00306BE0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1633)] = {0x006D8778, 0x006D877C, 0x006D8790, 0x006D8794, 0x006D87CC, 0x006D87D0, 0x001C002C, 0x003220D0, 0x0030EF30, 0x00306B70, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1634)] = {0x006D8798, 0x006D879C, 0x006D87B0, 0x006D87B4, 0x006D87EC, 0x006D87F0, 0x001C002C, 0x00322150, 0x0030EFB0, 0x00306BF0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1635)] = {0x006D8798, 0x006D879C, 0x006D87B0, 0x006D87B4, 0x006D87EC, 0x006D87F0, 0x001C002C, 0x003220E0, 0x0030EF40, 0x00306B80, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1636)] = {0x006D9198, 0x006D919C, 0x006D91B0, 0x006D91B4, 0x006D91EC, 0x006D91F0, 0x001C002C, 0x00322D40, 0x0030FBA0, 0x003065A0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1637)] = {0x006DA338, 0x006DA33C, 0x006DA350, 0x006DA354, 0x006DA38C, 0x006DA390, 0x001C002C, 0x003228B0, 0x0030FEF0, 0x003068F0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1638)] = {0x006DAC58, 0x006DAC5C, 0x006DAC70, 0x006DAC74, 0x006DACAC, 0x006DACB0, 0x001C002C, 0x00322E00, 0x00310440, 0x00306E40, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1639)] = {0x006DA198, 0x006DA19C, 0x006DA1B0, 0x006DA1B4, 0x006DA1EC, 0x006DA1F0, 0x001C002C, 0x00322F10, 0x00310550, 0x00306F50, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1640)] = {0x006DB498, 0x006DB49C, 0x006DB4B0, 0x006DB4B4, 0x006DB4EC, 0x006DB4F0, 0x001C002C, 0x00323160, 0x003107B0, 0x003071B0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1641)] = {0x006DB678, 0x006DB67C, 0x006DB690, 0x006DB694, 0x006DB6CC, 0x006DB6D0, 0x001C002C, 0x00322FD0, 0x00310590, 0x00306F90, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1642)] = {0x006DB818, 0x006DB81C, 0x006DB830, 0x006DB834, 0x006DB86C, 0x006DB870, 0x001C002C, 0x00323000, 0x003105C0, 0x00306FC0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1643)] = {0x006DB618, 0x006DB61C, 0x006DB630, 0x006DB634, 0x006DB66C, 0x006DB670, 0x001C002C, 0x00322E10, 0x00310430, 0x00306E30, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1644)] = {0x00786DF0, 0x00786DEC, 0x00786DD8, 0x00786DD4, 0x00786D80, 0x00786D7C, 0x001C002C, 0x003486D0, 0x00334490, 0x00322C90, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1645)] = {0x00788DF0, 0x00788DEC, 0x00788DD8, 0x00788DD4, 0x00788D80, 0x00788D7C, 0x001C002C, 0x0034A240, 0x00336000, 0x00324800, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1646)] = {0x00788DF0, 0x00788DEC, 0x00788DD8, 0x00788DD4, 0x00788D80, 0x00788D7C, 0x001C002C, 0x0034A430, 0x003361F0, 0x003249F0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1647)] = {0x00787DF0, 0x00787DEC, 0x00787DD8, 0x00787DD4, 0x00787D98, 0x00787D94, 0x001C002C, 0x00349680, 0x003353D0, 0x00323B20, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1648)] = {0x007C5FB0, 0x007C5FAC, 0x007C5F98, 0x007C5F94, 0x007C5F58, 0x007C5F54, 0x001C002C, 0x0036A000, 0x00354D50, 0x003439C0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1649)] = {0x007C5FB0, 0x007C5FAC, 0x007C5F98, 0x007C5F94, 0x007C5F58, 0x007C5F54, 0x001C002C, 0x0036A0B0, 0x00354E00, 0x00343A70, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1650)] = {0x007C5FB0, 0x007C5FAC, 0x007C5F98, 0x007C5F94, 0x007C5F58, 0x007C5F54, 0x001C002C, 0x0036A430, 0x00355180, 0x00343DF0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1651)] = {0x007C7FB0, 0x007C7FAC, 0x007C7F98, 0x007C7F94, 0x007C7F58, 0x007C7F54, 0x001C002C, 0x0036A5F0, 0x00355330, 0x00343FA0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1652)] = {0x007C7FB0, 0x007C7FAC, 0x007C7F98, 0x007C7F94, 0x007C7F58, 0x007C7F54, 0x001C002C, 0x0036A860, 0x003555A0, 0x00344250, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1653)] = {0x007C9FF0, 0x007C9FEC, 0x007C9FD8, 0x007C9FD4, 0x007C9F98, 0x007C9F94, 0x001C002C, 0x0036BCD0, 0x00356A30, 0x00345690, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1654)] = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}, // note: 516.1654 was a Windows-only build, as the only change was fixing a DreamSeeker rendering bug
	[BYOND_VERSION_ADJUSTED(1655)] = {0x007C9FF0, 0x007C9FEC, 0x007C9FD8, 0x007C9FD4, 0x007C9F98, 0x007C9F94, 0x001C002C, 0x0036BD20, 0x00356A80, 0x003456E0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1656)] = {0x007CC030, 0x007CC02C, 0x007CC018, 0x007CC014, 0x007CBFD8, 0x007CBFD4, 0x001C002C, 0x0036D4E0, 0x00358240, 0x00346EA0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1657)] = {0x007CC030, 0x007CC02C, 0x007CC018, 0x007CC014, 0x007CBFD8, 0x007CBFD4, 0x001C002C, 0x0036D6A0, 0x00358400, 0x00347060, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1658)] = {0x007CC030, 0x007CC02C, 0x007CC018, 0x007CC014, 0x007CBFD8, 0x007CBFD4, 0x001C002C, 0x0036D810, 0x00358570, 0x003471D0, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1659)] = {0x007CC030, 0x007CC02C, 0x007CC018, 0x007CC014, 0x007CBFD8, 0x007CBFD4, 0x001C002C, 0x0036DCD0, 0x00358A30, 0x00347690, 0x00050505},
	[BYOND_VERSION_ADJUSTED(1660)] = {0x007CD030, 0x007CD02C, 0x007CD018, 0x007CD014, 0x007CCFD8, 0x007CCFD4, 0x001C002C, 0x0036E600, 0x00359360, 0x00347FC0, 0x00050505},
};

#endif

UTRACY_INTERNAL
void build_srclocs(void) {
#define byond_get_string(id) ((id) < *byond.strings_len ? *(*byond.strings + (id)) : NULL)
#define byond_get_misc(id) ((id) < *byond.miscs_len ? *(*byond.miscs + (id)) : NULL)
#define byond_get_procdef(id) ((id) < *byond.procdefs_len ? (*byond.procdefs) + (id) * byond.procdef_desc.size : NULL)
#define byond_get_procdef_path(procdef) *((int unsigned *)((procdef) + byond.procdef_desc.path))
#define byond_get_procdef_bytecode(procdef) *((int unsigned *)((procdef) + byond.procdef_desc.bytecode))

	for(int unsigned i=0; i<0x14000; i++) {
		char *name = NULL;
		char *function = "<?>";
		char *file = "<?.dm>";
		int unsigned line = 0xFFFFFFFFu;
		int unsigned color = 0x4444AF;

		char *procdef = byond_get_procdef(i);
		if(procdef != NULL) {
			struct string *str = byond_get_string(byond_get_procdef_path(procdef));
			if(str != NULL && str->data != NULL) {
				function = str->data;
			}

			struct misc *misc = byond_get_misc(byond_get_procdef_bytecode(procdef));
			if(misc != NULL) {
				int unsigned bytecode_len = misc->bytecode.len;
				int unsigned *bytecode = misc->bytecode.bytecode;
				if(bytecode_len >= 2) {
					if(bytecode[0x00] == 0x84) {
						int unsigned file_id = bytecode[0x01];
						struct string *file_str = byond_get_string(file_id);
						if(file_str != NULL && file_str->data != NULL) {
							file = file_str->data;
						}

						if(bytecode_len >= 4) {
							if(bytecode[0x02] == 0x85) {
								line = bytecode[0x03];
							}
						}
					}
				}
			}
		}

		srclocs[i] = (struct utracy_source_location) {
			.name = name,
			.function = function,
			.file = file,
			.line = line,
			.color = color
		};
	}

	srclocs[0x14000] = (struct utracy_source_location) {
		.name = NULL,
		.function = "ServerTick",
		.file = __FILE__,
		.line = __LINE__,
		.color = 0x44AF44
	};

	srclocs[0x14001] = (struct utracy_source_location) {
		.name = NULL,
		.function = "SendMaps",
		.file = __FILE__,
		.line = __LINE__,
		.color = 0x44AF44
	};

#undef byond_get_string
#undef byond_get_misc
#undef byond_get_procdef
#undef byond_get_procdef_path
#undef byond_get_procdef_bytecode
}

/* byond api */
static bool initialized = false;

UTRACY_EXTERNAL
char *UTRACY_WINDOWS_CDECL UTRACY_LINUX_CDECL init(int argc, char **argv) {
	(void) argc;
	(void) argv;

	printf("hello world?\n");

	if(initialized) {
		return "already initialized";
	}

	bool block_start = false;
	if (argc > 0 && strcmp(argv[0], "block") == 0) {
		block_start = true;
	}

	(void) UTRACY_MEMSET(&byond, 0, sizeof(byond));
	(void) UTRACY_MEMSET(&utracy, 0, sizeof(utracy));

	utracy.info.init_begin = utracy_tsc();

	if(0 != event_queue_init()) {
		LOG_DEBUG_ERROR;
		return "event_queue_init failed";
	}

	typedef int (*PFN_GETBYONDBUILD)(void);
	PFN_GETBYONDBUILD GetByondBuild;

#if defined(UTRACY_WINDOWS)
	char *byondcore = (char *) GetModuleHandleA("byondcore.dll");
	if(NULL == byondcore) {
		LOG_DEBUG_ERROR;
		return "unable to find base address of byondcore.dll";
	}

	GetByondBuild = (PFN_GETBYONDBUILD) GetProcAddress(
		(HMODULE) byondcore,
		"?GetByondBuild@ByondLib@@QAEJXZ"
	);
	if(NULL == GetByondBuild) {
		LOG_DEBUG_ERROR;
		return "unable to find GetByondBuild";
	}

#elif defined(UTRACY_LINUX)
	struct link_map *libbyond = dlopen("libbyond.so", RTLD_NOW | RTLD_NOLOAD);
	if(NULL == libbyond) {
		LOG_DEBUG_ERROR;
		return "unable to find base address of libbyond.so";
	}

	GetByondBuild = dlsym(libbyond, "_ZN8ByondLib13GetByondBuildEv");
	if(NULL == GetByondBuild) {
		LOG_DEBUG_ERROR;
		return "unable to find GetByondBuild";
	}

#endif

	int byond_build = GetByondBuild();
	if(byond_build < BYOND_MIN_BUILD || byond_build > BYOND_MAX_BUILD) {
		LOG_DEBUG_ERROR;
		return "byond version unsupported";
	}

	int unsigned const *const offsets = byond_offsets[BYOND_VERSION_ADJUSTED(byond_build)];

	for(int i=0; i<11; i++) {
		if(offsets[i] == 0) {
			LOG_DEBUG_ERROR;
			return "byond version unsupported";
		}
	}

	char unsigned prologues[3];

#if defined(UTRACY_WINDOWS)
	byond.strings = (void *) (byondcore + offsets[0]);
	byond.strings_len = (void *) (byondcore + offsets[1]);
	byond.miscs = (void *) (byondcore + offsets[2]);
	byond.miscs_len = (void *) (byondcore + offsets[3]);
	byond.procdefs = (void *) (byondcore + offsets[4]);
	byond.procdefs_len = (void *) (byondcore + offsets[5]);
	byond.procdef_desc.size = (offsets[6] >> 0) & 0xFF;
	byond.procdef_desc.path = (offsets[6] >> 8) & 0xFF;
	byond.procdef_desc.bytecode = (offsets[6] >> 16) & 0xFF;
	byond.exec_proc = (void *)(byondcore + offsets[7]);
	byond.server_tick = (void *)(byondcore + offsets[8]);
	byond.send_maps = (void *)(byondcore + offsets[9]);
	prologues[0] = (offsets[10] >> 0) & 0xFF;
	prologues[1] = (offsets[10] >> 8) & 0xFF;
	prologues[2] = (offsets[10] >> 16) & 0xFF;

#elif defined(UTRACY_LINUX)
	byond.strings = (void *) (libbyond->l_addr + offsets[0]);
	byond.strings_len = (void *) (libbyond->l_addr + offsets[1]);
	byond.miscs = (void *) (libbyond->l_addr + offsets[2]);
	byond.miscs_len = (void *) (libbyond->l_addr + offsets[3]);
	byond.procdefs = (void *) (libbyond->l_addr + offsets[4]);
	byond.procdefs_len = (void *) (libbyond->l_addr + offsets[5]);
	byond.procdef_desc.size = (offsets[6] >> 0) & 0xFF;
	byond.procdef_desc.path = (offsets[6] >> 8) & 0xFF;
	byond.procdef_desc.bytecode = (offsets[6] >> 16) & 0xFF;
	byond.exec_proc = (void *)(libbyond->l_addr + offsets[7]);
	byond.server_tick = (void *)(libbyond->l_addr + offsets[8]);
	byond.send_maps = (void *)(libbyond->l_addr + offsets[9]);
	prologues[0] = (offsets[10] >> 0) & 0xFF;
	prologues[1] = (offsets[10] >> 8) & 0xFF;
	prologues[2] = (offsets[10] >> 16) & 0xFF;

#endif

	LOG_INFO("byond build = %d\n", byond_build);

	byond.orig_exec_proc = hook((void *) exec_proc, byond.exec_proc, prologues[0], byond.trampoline.exec_proc);
	if(NULL == byond.orig_exec_proc) {
		LOG_DEBUG_ERROR;
		return "failed to hook exec_proc";
	}

	byond.orig_server_tick = hook((void *) server_tick, byond.server_tick, prologues[1], byond.trampoline.server_tick);
	if(NULL == byond.orig_server_tick) {
		LOG_DEBUG_ERROR;
		return "failed to hook server_tick";
	}

	byond.orig_send_maps = hook((void *) send_maps, byond.send_maps, prologues[2], byond.trampoline.send_maps);
	if(NULL == byond.orig_send_maps) {
		LOG_DEBUG_ERROR;
		return "failed to hook send_maps";
	}

#if defined(UTRACY_WINDOWS)
	DWORD old_protect;
	if(0 == VirtualProtect(&byond.trampoline, UTRACY_PAGE_SIZE, PAGE_EXECUTE_READ, &old_protect)) {
		LOG_DEBUG_ERROR;
		return "failed to set trampoline access protection";
	}

#elif defined(UTRACY_LINUX)
	if(0 != mprotect(&byond.trampoline, UTRACY_PAGE_SIZE, PROT_READ | PROT_EXEC)) {
		LOG_DEBUG_ERROR;
		return "failed to set trampoline access protection";
	}

#endif

	build_srclocs();

	utracy.quit = create_event_pipe(true, 0);
	if (utracy.quit == 0) {
		LOG_DEBUG_ERROR;
		return "create_event_pipe(utracy.quit) failed";
	}

#if defined(UTRACY_LINUX)
	linux_main_tid = syscall(__NR_gettid);

	struct stat st = { 0 };
	if (stat("./data/profiler", &st) == -1) {
		if (stat("./data", &st) == -1) {
			if (0 != mkdir("./data", 0777)) {
				LOG_DEBUG_ERROR;
				return "failed to create data directory";
			}
		}

		if (0 != mkdir("./data/profiler", 0777)) {
			LOG_DEBUG_ERROR;
			return "failed to create data/profiler directory";
		}
	}
#elif defined(UTRACY_WINDOWS)
	(void) CreateDirectoryW(L".\\data", NULL);
	(void) CreateDirectoryW(L".\\data\\profiler", NULL);
#endif

#ifndef MAX_PATH
#define MAX_PATH 260 // same as windows
#endif

	event_pipe_t* profiler_connected_event = NULL;
	if (block_start) {
		profiler_connected_event = create_event_pipe(true, 0);
		if (profiler_connected_event == 0) {
			LOG_DEBUG_ERROR;
			return "create_event_pipe(profiler_connected_event) failed";
		}
	}

	static char ffilename[MAX_PATH];
	memset(ffilename, 0, MAX_PATH);
	snprintf(ffilename, MAX_PATH, "./data/profiler/%llu.utracy", utracy_tsc());
	utracy.fstream = fopen(ffilename, "wb");
	if(NULL == utracy.fstream) {
		LOG_DEBUG_ERROR;
		return "fopen failed";
	}

	utracy.info.resolution = calibrate_resolution();
	utracy.info.delay = calibrate_delay();
	utracy.info.multiplier = calibrate_multiplier();
	utracy.info.epoch = unix_timestamp();
	utracy.info.exec_time = unix_timestamp();
	utracy.info.init_end = utracy_tsc();

	thrd_t thread;
    if (thrd_create(&thread, utracy_server_thread_start, (void*)profiler_connected_event) != thrd_success) {
        LOG_DEBUG_ERROR;
        if (profiler_connected_event) {
            close_event_pipe(profiler_connected_event);
        }
        return "thread creation failed";
    }

    utracy.thread = thread;

	initialized = true;

	if (block_start) {
		printf("blocking until initialized\n");
        wait_for_event_pipe(profiler_connected_event, -1);
		printf("initialized, unblocking\n");
        close_event_pipe(profiler_connected_event);
    }

	return ffilename;
}

UTRACY_EXTERNAL
char *UTRACY_WINDOWS_CDECL UTRACY_LINUX_CDECL destroy(int argc, char **argv) {
	(void) argc;
	(void) argv;

	if (!initialized) {
        return "not initialized";
    } else if (utracy.fstream == NULL) {
		return "file stream closed";
	} else if (utracy.quit == NULL) {
		return "already shutting down";
	}

    set_event_pipe(utracy.quit);
    
    int thread_result;
    if (thrd_join(utracy.thread, &thread_result) != thrd_success) {
        LOG_DEBUG_ERROR;
        return "thread join failed";
    }

    close_event_pipe(utracy.quit);
	utracy.quit = NULL;
	FILE* fstream = utracy.fstream;
	utracy.fstream = NULL;
	utracy_flush(fstream);
    fclose(fstream);
    initialized = false;

    return "0";
}

UTRACY_EXTERNAL
char *UTRACY_WINDOWS_CDECL UTRACY_LINUX_CDECL flush(int argc, char **argv) {
	(void) argc;
	(void) argv;

	if(!initialized) {
		return "not initialized";
	} else if(utracy.fstream == NULL) {
		return "file stream closed";
	} else if (utracy.quit == NULL) {
		return "already shutting down";
	}

	// Then ensure it's written to disk
	int fd = _fileno(utracy.fstream);
	if(fd == -1) {
		LOG_DEBUG_ERROR;
		return "failed to get file descriptor";
	}

#if defined(UTRACY_WINDOWS)
	if(_commit(fd) != 0) {
		LOG_DEBUG_ERROR;
		return "failed to commit file to disk";
	}
#elif defined(UTRACY_LINUX)
	if(fsync(fd) != 0) {
		LOG_DEBUG_ERROR;
		return "failed to sync file to disk";
	}
#endif

	return "0";
}

#if (__STDC_HOSTED__ == 0) && defined(UTRACY_WINDOWS)
BOOL WINAPI DllMainCRTStartup(HINSTANCE instance, DWORD reason, LPVOID reserved) {
	return TRUE;
}
#endif
