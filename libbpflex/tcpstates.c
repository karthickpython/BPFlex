#include <argp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "btf_helpers.h"
#include "tcpstates.h"
#include "tcpstates.skel.h"
#include "trace_helpers.h"
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h>
#include <sys/stat.h>

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100
#define warn(...) fprintf(stderr, __VA_ARGS__)
#define TIME_THRESHOLD 3
static volatile sig_atomic_t exiting = 0;
static bool verbose = false;

static const char *tcp_states[] = {
	[1] = "ESTABLISHED",
	[2] = "SYN_SENT",
	[3] = "SYN_RECV",
	[4] = "FIN_WAIT1",
	[5] = "FIN_WAIT2",
	[6] = "TIME_WAIT",
	[7] = "CLOSE",
	[8] = "CLOSE_WAIT",
	[9] = "LAST_ACK",
	[10] = "LISTEN",
	[11] = "CLOSING",
	[12] = "NEW_SYN_RECV",
	[13] = "UNKNOWN",
};

enum {
        TCP_ESTABLISHED = 1,
        TCP_SYN_SENT,
        TCP_SYN_RECV,
        TCP_FIN_WAIT1,
        TCP_FIN_WAIT2,
        TCP_TIME_WAIT,
        TCP_CLOSE,
        TCP_CLOSE_WAIT,
        TCP_LAST_ACK,
        TCP_LISTEN,
        TCP_CLOSING,    /* Now a valid state */
        TCP_NEW_SYN_RECV,

        TCP_MAX_STATES  /* Leave at the end! */
};


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

char parsed_data[200];
char path[150];
int trans_time;
FILE *ptr;
int INI_Parser(char *param){

        ptr = fopen("agent.cfg.ini","r");
        if(ptr == NULL){
                perror("Error opening file");
                return 1;
        }
        char my_file[5000];
        char a[100] = "file_size";
        int counter = 0;
        bool start = false;
        int path_count = 0;
        while(fgets(my_file, 5000, ptr)){

         if(strstr(my_file, param)){
           while(my_file[counter] != '\0'){
              if(my_file[counter] == '='){
                      start = true;
                      counter++;
                      continue;
              }
              if(start){
                      if((my_file[counter] == ' ') || (my_file[counter] == '\n')){
                              counter++;
                              continue;
                      }
                      parsed_data[path_count++] = my_file[counter];
              }

               counter++;
         }
           parsed_data[path_count] = '\0';
        }
        }
        fclose(ptr);

        return 0;
}
   

FILE *file;

long long file_size_check(FILE *file){
     
    long long fileSize;
    
    long long currentPosition = ftell(file);
    
    fseek(file, 0, SEEK_END);

    fileSize = ftell(file);

    fseek(file, currentPosition, SEEK_SET);
    return fileSize;
}

int copyFile(const char* sourceFilePath, const char* destinationFilePath) {
    FILE* sourceFile = fopen(sourceFilePath, "rb");
    if (sourceFile == NULL) {
        perror("Source file opening error");
        return 1; 
    }

    FILE* destinationFile = fopen(destinationFilePath, "wb");
    if (destinationFile == NULL) {
        perror("Destination file opening error");
        fclose(sourceFile); 
        return 1; 
    }

    char buffer[1024];
    size_t bytesRead;
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), sourceFile)) > 0) {
        fwrite(buffer, 1, bytesRead, destinationFile);
    }

    fclose(destinationFile);

    return 0; 
}

bool delete_file(char *filename){
        
     if (remove(filename) == 0) {
        return true;
    } else {
        return false;
    }
}
int Parsed_time;
bool isFiveMinutesPassed() {
    static time_t firstCallTime = 0; // Static variable to store the time of the first call
    time_t currentTime;

    time(&currentTime);
    if (firstCallTime == 0) {
        firstCallTime = currentTime;
        return false; 
    }

    if (currentTime - firstCallTime >= Parsed_time) {
        firstCallTime = currentTime; // Reset the timer
        return true;
    }

    return false;
}

int uniqueNumber() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    long long milliseconds = tv.tv_sec * 1000LL + tv.tv_usec / 1000; 

    srand(milliseconds);

    return rand();
}

char file_name[150];
bool flag_new_file = true;
int FILE_SIZE;
bool write_tuples(struct event *e)
{
    char saddr[26], daddr[26];
    struct tm *tm;
    time_t t;
    char ts[32];
    int base_time = 0;
    time(&t);
    tm = localtime(&t);
    int local_minutes = tm->tm_min;

    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    char* txt = ".txt";
    inet_ntop(e->family, &e->saddr, saddr, sizeof(saddr));
    inet_ntop(e->family, &e->daddr, daddr, sizeof(daddr));

    char destination_path[500];
    
    if(flag_new_file){ 
        sprintf(file_name,"S247_eBPF_%d%s",uniqueNumber(), txt);
     }

    file = fopen(file_name,"ab");
    if (file == NULL) {
        perror("Error opening file");
        return false;
    }

    fprintf(file, "%s|%s|%s|%d|%s|%d|%d|%d|%.3f\n", ts, e->task, saddr, e->sport, daddr, e->dport, e->tid, e->pid, (double)e->delta_us / 1000 );
    if((isFiveMinutesPassed()) || (file_size_check(file) >= FILE_SIZE)){
         snprintf(destination_path, sizeof(destination_path), "%s/%s",path,file_name);
	 printf("desti path %s", destination_path);
         copyFile(file_name, destination_path);
         if(!delete_file(file_name))
               perror("Error deleting  file");
	 flag_new_file = true; 
    }else{
	    flag_new_file = false;
    } 
   
    fclose(file);
}

int socket_handle(struct event *e)
{
        int state;

        if(e->conn_passive == 1)
	     write_tuples(e);

	state = e->newstate;
	if(state == TCP_ESTABLISHED)
	    write_tuples(e);
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct event *e = data;
        socket_handle(e);             
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	struct perf_buffer *pb = NULL;
	struct tcpstates_bpf *obj;
	int err;

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		warn("failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}
        printf("Printing path details \n");
	INI_Parser("path");
	strcpy(path,parsed_data);
	printf("%s\n",path);
        INI_Parser("seconds");
	Parsed_time = atoi(parsed_data);
	printf("%d\n", Parsed_time);
	INI_Parser("file_size");
        FILE_SIZE = atoi(parsed_data);
	printf("%d\n", FILE_SIZE);

	obj = tcpstates_bpf__open_opts(&open_opts);
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}


	err = tcpstates_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}


	err = tcpstates_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}
       
	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = - errno;
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}
        isFiveMinutesPassed();

	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warn("error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	tcpstates_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
