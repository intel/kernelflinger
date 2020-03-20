#include <efi.h>
#include <efilib.h>
#include <lib.h>
#include "openssl_support.h"

FILE  *__sF = NULL;
typedef UINT32 uid_t;
typedef int pid_t;

int errno __attribute__((weak));
int errno = 0;
int *__errno(void)
	__attribute__((weak));
int *__errno(void)
{
	return &errno;
}

int atoi(const char *str)
	__attribute__((weak));
int atoi(const char *str)
{
	int u;
	char c;

	/* skip preceding white space */
	while (*str == ' ')
		str ++;

	/* convert digits */
	u = 0;
	while ((c = *(str++))) {
		if (c >= '0' && c <= '9')
			u = (u * 10) + c - '0';
		else
			break;
	}

	return u;
}

int fprintf(FILE *f, const char *s, ...)
	__attribute__((weak));
int fprintf(FILE *f, const char *s, ...)
{
	error(L"Error: STUBBED %a", __func__);
	return 0;
}

int ioctl(int d, int request, ...)
	__attribute__((weak));
int ioctl(int d, int request, ...)
{
	error(L"Error: STUBBED %a", __func__);
	return 0;
}

typedef void (*sighandler_t)(int);
sighandler_t bsd_signal(int signum, sighandler_t handler)
{
	error(L"Error: STUBBED %a", __func__);
	return NULL;
}

void __assert2(const char *file, int line, const char *function,
	       const char *failed_expression)
{
	error(L"Assertion '%a' failed at %a:%a:%d",
	      failed_expression, file, function, line);
}

void *bsearch(const void *key, const void *base,
	      size_t nmemb, size_t size,
	      int (*compar)(const void *, const void *))
{
	UINTN start, end, middle;
	void *current;
	int ret;

	for (start = 0, end = nmemb ; start < end;) {
		middle = start + (end - start) / 2;

		current = (void *)base + (middle * size);
		ret = compar(key, current);
		if (ret < 0) {
			end = middle;
			continue;
		}
		if (ret > 0) {
			start = middle + 1;
			continue;
		}

		return current;
	}

	return NULL;
}

int fcntl(int fd, int cmd, ... /* arg */ )
	__attribute__((weak));
int fcntl(int fd, int cmd, ... /* arg */ )
{
	return -1;
}

int dup(int oldfd)
	__attribute__((weak));
int dup(int oldfd)
{
	return -1;
}

static const char __ctype_[256];
const char *_ctype_ = __ctype_;

int strcasecmp(const char *c, const char *s)
	__attribute__((weak));
int strcasecmp(const char *c, const char *s)
{
	error(L"Error: STUBBED %a", __func__);
	return 0;
}

int sscanf(const char *buffer, const char *format, ...)
	__attribute__((weak));
int sscanf(const char *buffer, const char *format, ...)
{
	error(L"Error: STUBBED %a", __func__);
	return 0;
}

size_t fwrite(const void *buffer, size_t size, size_t count, FILE *stream)
	__attribute__((weak));
size_t fwrite(const void *buffer, size_t size, size_t count, FILE *stream)
{
	error(L"Error: STUBBED %a", __func__);
	return 0;
}

size_t __strlen_chk(const char *s, size_t slen)
	__attribute__((weak));
size_t __strlen_chk(const char *s, size_t slen)
{
	size_t len = strlen(s);
	if (len >= slen)
		error(L"Error: %a overflow", __func__);
	return len;
}

void * __memset_chk(void* dest, int c, size_t n, size_t dest_len)
	__attribute__((weak));
void * __memset_chk(void* dest, int c, size_t n, size_t dest_len)
{
	if (dest_len < n)
		panic(L"%a Error: dest_len(%d) is less than n(%d)", __func__, dest_len, n);

	return memset(dest, c, n);
}

char *fgets(char * dest, int size, FILE* stream)
	__attribute__((weak));
char *fgets(char * dest, int size, FILE* stream)
{
	error(L"Error: STUBBED %a", __func__);
	return NULL;
}

char *__fgets_chk(char * dest, int size, int strsize, FILE* stream)
	__attribute__((weak));
char *__fgets_chk(char * dest, int size, int strsize, FILE* stream)
{
	error(L"Error: STUBBED %a", __func__);
	return NULL;
}

int fclose(FILE *f)
	__attribute__((weak));
int fclose(FILE *f)
{
	error(L"Error: STUBBED %a", __func__);
	return 0;
}

size_t fread(void *b, size_t c, size_t i, FILE *f)
	__attribute__((weak));
size_t fread(void *b, size_t c, size_t i, FILE *f)
{
	error(L"Error: STUBBED %a", __func__);
	return 0;
}

int ferror(FILE *f)
	__attribute__((weak));
int ferror(FILE *f)
{
	error(L"Error: STUBBED %a", __func__);
	return 0;
}

FILE *fopen(const char *c, const char *m)
	__attribute__((weak));
FILE *fopen(const char *c, const char *m)
{
	error(L"Error: STUBBED %a", __func__);
	return NULL;
}

int fseek(FILE *fp, long offset, int whence)
	__attribute__((weak));
int fseek(FILE *fp, long offset, int whence)
{
	error(L"Error: STUBBED %a", __func__);
	return 0;
}

int feof(FILE *f)
	__attribute__((weak));
int feof(FILE *f)
{
	error(L"Error: STUBBED %a", __func__);
	return 0;
}

int fflush(FILE *fp)
	__attribute__((weak));
int fflush(FILE *fp)
{
	error(L"Error: STUBBED %a", __func__);
	return 0;
}

char *strrchr(const char *str, int c)
	__attribute__((weak));
char *strrchr(const char *str, int c)
{
	char *save;

	for (save = NULL; ; ++str) {
		if (*str == c)
			save = (char *)str;
		if (*str == 0)
			return (save);
	}
	return NULL;
}

char *getenv(const char *varname)
	__attribute__((weak));
char *getenv(const char *varname)
{
	return NULL;
}

pid_t getpid(void)
	__attribute__((weak));
pid_t getpid(void)
{
	error(L"Error: STUBBED %a", __func__);
	return 0;
}

int vfprintf(FILE *stream, const char *format, va_list arg)
	__attribute__((weak));
int vfprintf(FILE *stream, const char *format, va_list arg)
{
	error(L"Error: STUBBED %a", __func__);
	return 0;
}

int vsnprintf(char *str, size_t size, const char *format, va_list ap)
	__attribute__((weak));
int vsnprintf(char *str, size_t size, const char *format, va_list ap)
{
	char *efi_format;
	size_t i;
	int ret;

	efi_format = strdup(format);
	if (!efi_format)
		return -1;

	/* Replace "%s" with "%a" */
	for (i = 0; i < strlen(efi_format) - 2; i++) {
		if (!memcmp("%%", &efi_format[i], 2)) {
			i++;
			continue;
		}
		if (!memcmp("%s", &efi_format[i], 2))
			efi_format[++i] = 'a';
	}

	ret = efi_vsnprintf(str, size, efi_format, ap);
	FreePool(efi_format);
	return ret;
}

int __vsnprintf_chk(char *str, size_t size, int flags, size_t slen,
			const char *format, va_list ap)
			__attribute__((weak));
int __vsnprintf_chk(char *str, size_t size, int flags, size_t slen,
			const char *format, va_list ap)
{
	if (slen < size)
		panic(L"%a Error: slen(%d) is less than size(%d)", __func__, slen, size);

	return vsnprintf(str, size, format, ap);
}
void abort(void)
{
	error(L"Error: STUBBED %a", __func__);
}

char *strerror(int errnum)
	__attribute__((weak));
char *strerror(int errnum)
{
	error(L"Error: STUBBED %a", __func__);
	return NULL;
}

void * __memcpy_chk(void* dest, const void* src,
			size_t copy_amount, size_t dest_len)
			__attribute__((weak));
void * __memcpy_chk(void* dest, const void* src,
			size_t copy_amount, size_t dest_len)
{
	if (dest_len < copy_amount) {
		panic(L"%a Error: dest_len(%d) is less than copy_amount(%d)",
			__func__, dest_len, copy_amount);
	}

	return memcpy(dest, src, copy_amount);
}

#define SECSPERMIN	60
#define MINSPERHOUR	60
#define HOURSPERDAY	24
#define SECSPERHOUR	(SECSPERMIN * MINSPERHOUR)
#define SECSPERDAY	((int) SECSPERHOUR * HOURSPERDAY)

#define DAYSPERWEEK	7
#define DAYSPERNYEAR	365
#define DAYSPERLYEAR	366
#define MONSPERYEAR	12
#define TM_THURSDAY	4

#define EPOCH_YEAR	1970
#define EPOCH_WDAY	TM_THURSDAY

#define TYPE_SIGNED(type) (((type) -1) < 0)

#define	INT_MIN		(-0x7fffffff-1)	/* min value for an int */
#define	INT_MAX		0x7fffffff	/* max value for an int */
#define TM_YEAR_BASE	1900

static const int mon_lengths[2][MONSPERYEAR] = {
	{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
	{ 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
};

static const int year_lengths[2] = {
	DAYSPERNYEAR, DAYSPERLYEAR
};

#define isleap(y) (((y) % 4) == 0 && (((y) % 100) != 0 || ((y) % 400) == 0))

static int leaps_thru_end_of(register const int y)
{
	return (y >= 0) ? (y / 4 - y / 100 + y / 400) :
		-(leaps_thru_end_of(-(y + 1)) + 1);
}

static int
increment_overflow(int *const ip, int j)
{
	register int const i = *ip;

	/* If i >= 0 there can only be overflow if i + j > INT_MAX
	 * or if j > INT_MAX - i; given i >= 0, INT_MAX - i cannot overflow.
	 * If i < 0 there can only be overflow if i + j < INT_MIN
	 * or if j < INT_MIN - i; given i < 0, INT_MIN - i cannot overflow.
	 */
	if ((i >= 0) ? (j > INT_MAX - i) : (j < INT_MIN - i))
		return 1;
	*ip += j;
	return 0;
}

struct tm
{
	int tm_sec;			/* Seconds.	[0-60] (1 leap second) */
	int tm_min;			/* Minutes.	[0-59] */
	int tm_hour;			/* Hours.	[0-23] */
	int tm_mday;			/* Day.		[1-31] */
	int tm_mon;			/* Month.	[0-11] */
	int tm_year;			/* Year	- 1900.  */
	int tm_wday;			/* Day of week.	[0-6] */
	int tm_yday;			/* Days in year.[0-365]	*/
	int tm_isdst;			/* DST.		[-1/0/1]*/
	long int tm_gmtoff;		/* Seconds east of UTC.  */
	char *tm_zone;		/* Timezone abbreviation.  */
};

struct tm *gmtime_r(const time_t *timep, struct tm *tmp)
	__attribute__((weak));
struct tm *gmtime_r(const time_t *timep, struct tm *tmp)
{
	time_t tdays;
	int idays;  /* unsigned would be so 2003 */
	long long rem;
	int y;
	const int *ip;

	y = EPOCH_YEAR;
	tdays = *timep / SECSPERDAY;
	rem = *timep - tdays * SECSPERDAY;
	while (tdays < 0 || tdays >= year_lengths[isleap(y)]) {
		int newy;
		time_t tdelta;
		int idelta;
		int leapdays;

		tdelta = tdays / DAYSPERLYEAR;
		if (! ((! TYPE_SIGNED(time_t) || INT_MIN <= tdelta)
		       && tdelta <= INT_MAX))
			return NULL;
		idelta = tdelta;
		if (idelta == 0)
			idelta = (tdays < 0) ? -1 : 1;
		newy = y;
		if (increment_overflow(&newy, idelta))
			return NULL;
		leapdays = leaps_thru_end_of(newy - 1) -
			leaps_thru_end_of(y - 1);
		tdays -= ((time_t) newy - y) * DAYSPERNYEAR;
		tdays -= leapdays;
		y = newy;
	}
	{
		int seconds;

		seconds = tdays * SECSPERDAY;
		tdays = seconds / SECSPERDAY;
		rem += seconds - tdays * SECSPERDAY;
	}
	 /* Given the range, we can now fearlessly cast... */
	idays = tdays;

	while (rem < 0) {
		rem += SECSPERDAY;
		--idays;
	}
	while (rem >= SECSPERDAY) {
		rem -= SECSPERDAY;
		++idays;
	}
	while (idays < 0) {
		if (increment_overflow(&y, -1))
			return NULL;
		idays += year_lengths[isleap(y)];
	}
	while (idays >= year_lengths[isleap(y)]) {
		idays -= year_lengths[isleap(y)];
		if (increment_overflow(&y, 1))
			return NULL;
	}
	tmp->tm_year = y;
	if (increment_overflow(&tmp->tm_year, -TM_YEAR_BASE))
		return NULL;
	tmp->tm_yday = idays;

	/* The "extra" mods below avoid overflow problems. */
	tmp->tm_wday = EPOCH_WDAY +
		((y - EPOCH_YEAR) % DAYSPERWEEK) *
		(DAYSPERNYEAR % DAYSPERWEEK) +
		leaps_thru_end_of(y - 1) -
		leaps_thru_end_of(EPOCH_YEAR - 1) +
		idays;
	tmp->tm_wday %= DAYSPERWEEK;
	if (tmp->tm_wday < 0)
		tmp->tm_wday += DAYSPERWEEK;
	tmp->tm_hour = (int) (rem / SECSPERHOUR);
	rem %= SECSPERHOUR;
	tmp->tm_min = (int) (rem / SECSPERMIN);
	/* A positive leap second requires a special
	 * representation. This uses "... ??:59:60" et seq. */
	tmp->tm_sec = (int) (rem % SECSPERMIN);
	ip = mon_lengths[isleap(y)];
	for (tmp->tm_mon = 0; idays >= ip[tmp->tm_mon]; ++(tmp->tm_mon))
		idays -= ip[tmp->tm_mon];
	tmp->tm_mday = (int) (idays + 1);
	tmp->tm_isdst = 0;
	tmp->tm_gmtoff = 0;
	tmp->tm_zone = "GMT";
	return tmp;
}

static UINTN CumulativeDays[2][14] = {
	{
		0,
		0,
		31,
		31 + 28,
		31 + 28 + 31,
		31 + 28 + 31 + 30,
		31 + 28 + 31 + 30 + 31,
		31 + 28 + 31 + 30 + 31 + 30,
		31 + 28 + 31 + 30 + 31 + 30 + 31,
		31 + 28 + 31 + 30 + 31 + 30 + 31 + 31,
		31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30,
		31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31,
		31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31 + 30,
		31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31 + 30 + 31
	},
	{
		0,
		0,
		31,
		31 + 29,
		31 + 29 + 31,
		31 + 29 + 31 + 30,
		31 + 29 + 31 + 30 + 31,
		31 + 29 + 31 + 30 + 31 + 30,
		31 + 29 + 31 + 30 + 31 + 30 + 31,
		31 + 29 + 31 + 30 + 31 + 30 + 31 + 31,
		31 + 29 + 31 + 30 + 31 + 30 + 31 + 31 + 30,
		31 + 29 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31,
		31 + 29 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31 + 30,
		31 + 29 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31 + 30 + 31
	}
};

time_t time(time_t *timer)
	__attribute__((weak));
time_t time(time_t *timer)
{
	EFI_TIME  Time;
	UINTN     Year;

	/* Get the current time and date information */
	uefi_call_wrapper(RT->GetTime, 2, &Time, NULL);

	/* Years Handling
	 * UTime should now be set to 00:00:00 on Jan 1 of the current year. */
	for (Year = 1970, *timer = 0; Year != Time.Year; Year++)
		*timer = *timer + (time_t)(CumulativeDays[isleap(Year)][13] * SECSPERDAY);

	/* Add in number of seconds for current Month, Day, Hour, Minute, Seconds, and TimeZone adjustment */
	*timer = *timer +
		(time_t)((Time.TimeZone != EFI_UNSPECIFIED_TIMEZONE) ? (Time.TimeZone * 60) : 0) +
		(time_t)(CumulativeDays[isleap(Time.Year)][Time.Month] * SECSPERDAY) +
		(time_t)(((Time.Day > 0) ? Time.Day - 1 : 0) * SECSPERDAY) +
		(time_t)(Time.Hour * SECSPERHOUR) +
		(time_t)(Time.Minute * 60) +
		(time_t)Time.Second;

	return *timer;
}

char *strcat(char *dest, const char *src)
	__attribute__((weak));
char *strcat(char *dest, const char *src)
{
	error(L"Error: STUBBED %a", __func__);
	return NULL;
}

char * __strcat_chk(char* __restrict dest, const char* __restrict src,
		    size_t dest_buf_size)
{
	error(L"Error: STUBBED %a", __func__);
	return NULL;
}

int open(const char * pathname, int flags, ...)
	__attribute__((weak));
int open(const char * pathname, int flags, ...)
{
	error(L"Error: STUBBED %a", __func__);
	return 0;
}

int __open_2(const char *file, int oflag)
	__attribute__((weak));
int __open_2(const char *file, int oflag)
{
	error(L"Error: STUBBED %a", __func__);
	return 0;
}

int poll(void)
	__attribute__((weak));
int poll(void)
{
	error(L"Error: STUBBED %a", __func__);
	return 0;
}

ssize_t read(int f, void *b, size_t c)
	__attribute__((weak));
ssize_t read(int f, void *b, size_t c)
{
	error(L"Error: STUBBED %a", __func__);
	return 0;
}

ssize_t __read_chk(int f, void *b, size_t c, size_t buflen)
	__attribute__((weak));
ssize_t __read_chk(int f, void *b, size_t c, size_t buflen)
{
	error(L"Error: STUBBED %a", __func__);
	return 0;
}

uid_t getuid(void)
	__attribute__((weak));
uid_t getuid(void)
{
	error(L"Error: STUBBED %a", __func__);
	return 0;
}

long strtol(const char *nptr, char **endptr, int base)
	__attribute__((weak));
long strtol(const char *nptr, char **endptr, int base)
{
	error(L"Error: STUBBED %a", __func__);
	return 0;
}

int socket(int domain, int type, int protocol)
	__attribute__((weak));
int socket(int domain, int type, int protocol)
{
	error(L"Error: STUBBED %a", __func__);
	return 0;
}

int connect(void)
	__attribute__((weak));
int connect(void)
{
	error(L"Error: STUBBED %a", __func__);
	return 0;
}

ssize_t write(int f, const void *b, size_t l)
	__attribute__((weak));
ssize_t write(int f, const void *b, size_t l)
{
	error(L"Error: STUBBED %a", __func__);
	return 0;
}

int close(int f)
	__attribute__((weak));
int close(int f)
{
	error(L"Error: STUBBED %a", __func__);
	return 0;
}

int fputs(const char *s, FILE *f)
	__attribute__((weak));
int fputs(const char *s, FILE *f)
{
	error(L"Error: STUBBED %a", __func__);
	return 0;
}

void *signal(int i, void *s)
	__attribute__((weak));
void *signal(int i, void *s)
{
	error(L"Error: STUBBED %a", __func__);
	return NULL;
}

int sigaction(int signum, const void *act,
	      void *oldact)
{
	error(L"Error: STUBBED %a", __func__);
	return 0;
}

int fileno(FILE *stream)
	__attribute__((weak));
int fileno(FILE *stream)
{
	error(L"Error: STUBBED %a", __func__);
	return 0;
}

int tcsetattr(int fd, int optional_actions,
	      const void *termios_p)
{
	error(L"Error: STUBBED %a", __func__);
	return 0;
}

long int ftell(FILE *__stream)
	__attribute__((weak));
long int ftell(FILE *__stream)
{
	error(L"Error: STUBBED %a", __func__);
	return 0;
}

void* localtime(const void* t)
	__attribute__((weak));
void* localtime(const void* t)
{
	error(L"Error: STUBBED %a", __func__);
	return NULL;
}

int fstat(int __fd, void *__buf)
	__attribute__((weak));
int fstat(int __fd, void *__buf)
{
	error(L"Error: STUBBED %a", __func__);
	return 0;
}

char* __strchr_chk(const char* p, int ch, size_t s_len)
	__attribute__((weak));
char* __strchr_chk(const char* p, int ch, size_t s_len)

{
	error(L"Error: STUBBED %a", __func__);
	return NULL;
}

int tcgetattr(int fd, void *termios_p)
	__attribute__((weak));
int tcgetattr(int fd, void *termios_p)
{
	error(L"Error: STUBBED %a", __func__);
	return 0;
}

/* UEFI ReallocatePool needs the old size information, which we don't have.
 * These wrappers of malloc, free and realloc keeps track of allocated
 * memory to be able to get the old size information.
 * The static table mem might be too small.
 * When this code has been written, we have counted a maximun of 450
 * allocated chunks during a secure boot use case */
typedef struct mem_chunk {
	void *addr;
	size_t size;
} mem_chunk_t;
static mem_chunk_t mem[1024];

static inline mem_chunk_t *search_mem(void *addr)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(mem) && mem[i].addr != addr; i++)
		;

	if (i == ARRAY_SIZE(mem))
		return NULL;
	return &mem[i];
}

void *malloc(size_t size)
	__attribute__((weak));
void *malloc(size_t size)
{
	mem_chunk_t *mc;

	mc = search_mem(NULL);
	if (!mc) {
		error(L"malloc failed, wrapper allocator is full!");
		return NULL;
	}

	mc->addr = AllocatePool(size);
	mc->size = size;
	return mc->addr;
}

void free(void *addr)
	__attribute__((weak));
void free(void *addr)
{
	mem_chunk_t *mc;

	if (!addr)
		return;

	mc = search_mem(addr);
	if (!mc) {
		error(L"Tried to free an unknown pointer");
		return;
	}

	FreePool(addr);
	mc->addr = NULL;
}

void *realloc(void *ptr, size_t size)
	__attribute__((weak));
void *realloc(void *ptr, size_t size)
{
	mem_chunk_t *mc;

	mc = search_mem(ptr);
	if (!mc) {
		error(L"Tried to realloc an unknown pointer");
		return NULL;
	}

	mc->addr = ReallocatePool(ptr, (UINTN)mc->size, (UINTN) size);
	mc->size = size;
	return mc->addr;
}

void *memchr(const void *s, int c, size_t n)
	__attribute__((weak));
void *memchr(const void *s, int c, size_t n)
{
	const unsigned char *p = s;

	if (n) {
		for( ; n; n--, p++)
			if (*p == (unsigned char)c)
				return (void *) p;
	}

	return NULL;
}


void perror ( const char * str )
{
	error(L"%a: errno=%d", str, errno);
}

int printf(int fd, int cmd, ... /* arg */ )
       __attribute__((weak));
int printf(int fd, int cmd, ... /* arg */ )
{
       error(L"Error: STUBBED %a", __func__);
       return -1;
}
