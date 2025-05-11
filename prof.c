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
#include "offsets/windows.h"
#elif defined(UTRACY_LINUX)
#include "offsets/linux.h"
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
