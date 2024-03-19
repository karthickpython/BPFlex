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
#include "tcpretrans.h"
#include "tcpretrans.skel.h"
#include "trace_helpers.h"
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>
#include <fcntl.h>

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

FILE *ebpf_debug;
FILE *ebpf_error;
char *ErrorPath;
char *ErrorDebug;
char temp_dir[500];
char lock_file[500];
int lock_fd = -1;
int log_files_init(const char *inputPath)
{   

    char outputPath[300];
    const char* findStr = "ebpf";
    const char* replaceStr = "logs";

    // Find the position of "ebpf" in the input path
    char* foundPosition = strstr(inputPath, findStr);

    if (foundPosition != NULL) {
        // Copy the part of the input path before "ebpf" to the output path
        strncpy(outputPath, inputPath, foundPosition - inputPath);

        // Concatenate "logs" to the output path
        strcat(outputPath, replaceStr);

        // Concatenate the part of the input path after "ebpf" to the output path
        strcat(outputPath, foundPosition + strlen(findStr));
    } else {
        // "ebpf" not found in the input path, copy the original path
        strcpy(outputPath, inputPath);
    }

    // Calculate the length of the input path
    size_t inputPathLen = strlen(inputPath);

    // Allocate memory for the new path (input path + "logs/")
    ErrorPath = (char*)malloc(inputPathLen + sizeof("/logs/ebpf_error.log"));
    ErrorDebug = (char*)malloc(inputPathLen + sizeof("/logs/ebpf_debug.log"));
    if ((ErrorPath == NULL) || (ErrorDebug == NULL)) {
        perror("malloc() error");
        return 0;
    }
    // Copy the input path to the new path
    strcpy(ErrorPath, outputPath);
    strcpy(ErrorDebug, outputPath);
    // Append "logs/" to the new path
    strcat(ErrorPath, "/ebpf_error.log");
    strcat(ErrorDebug, "/ebpf_debug.log");

     ebpf_error = fopen(ErrorPath,"w");
     if(ebpf_error == NULL){
        perror("Error opening file");
	return 0;
       }

     fprintf(ebpf_error,"**************log file created for errors****************\n");

     ebpf_debug = fopen(ErrorDebug,"w");
     if(ebpf_debug == NULL){
        perror("Error opening file");
	return 0;
      }

     fprintf(ebpf_debug,"***************log file created for debugs***************\n");

     fclose(ebpf_error);
     fclose(ebpf_debug);

    return 1;
}

int create_lock_file() {
    lock_fd = open(lock_file, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (lock_fd == -1) {
        if (errno == EEXIST) {
            fprintf(stderr, "Another instance is already running. Exiting.\n");
        } else {
            perror("Unable to create lock file");
        }
        exit(EXIT_FAILURE);
    }
    return lock_fd;
}

void remove_lock_file() {
    if (lock_fd != -1) {
        if (unlink(lock_file) == -1) {
            perror("Unable to remove lock file");
            // Handle the error if necessary
        }
        close(lock_fd);
    }
}
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
char config_path[256];
char cfg_path[500];
int trans_time;
FILE *ptr;
int INI_Parser(char *param){
        
        ptr = fopen(cfg_path,"r");
        if(ptr == NULL){
                printf("Error opening config file");
                return 1;
        }
        char my_file[5000];
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


FILE *file = NULL;

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
        printf("Source file opening error");
        return 1;
    }

    FILE* destinationFile = fopen(destinationFilePath, "wb");
    if (destinationFile == NULL) {
        printf("Destination file opening error");
        fclose(sourceFile);
        return 1;
    }

    char buffer[1024];
    size_t bytesRead;
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), sourceFile)) > 0) {
        fwrite(buffer, 1, bytesRead, destinationFile);
    }

    fclose(destinationFile);
    fclose(sourceFile);
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

char file_name[530];
bool flag_new_file = true;
int FILE_SIZE;
bool write_tuples(struct event *e)
{
    char saddr[26], daddr[26];
    struct tm *tm;
    time_t t;
    char ts[32];
    time(&t);
    tm = localtime(&t);

    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    char* txt = ".txt";
    inet_ntop(e->family, &e->saddr, saddr, sizeof(saddr));
    inet_ntop(e->family, &e->daddr, daddr, sizeof(daddr));

    char destination_path[700];
    char temp_path[300];
    if(flag_new_file){
	int rand = uniqueNumber();
        sprintf(file_name,"%s/247_eBPF_%d%s",temp_dir, rand, txt);
	sprintf(temp_path,"247_eBPF_%d%s",rand,txt);
     
    file = fopen(file_name,"ab");
    if (file == NULL) {
        perror("Error opening file");
	printf("Error Opening file for eBPF output");
        return false;
    }
    
    }

    printf("%s|%s|%s|%d|%s|%d|%d|%d|%.3f\n", ts, e->task, saddr, e->sport, daddr, e->dport, e->tid, e->pid, (double)e->delta_us / 1000 );
  /*  if((isFiveMinutesPassed()) || (file_size_check(file) >= FILE_SIZE)){
         snprintf(destination_path, sizeof(destination_path), "%s/%s",path, temp_path);
         copyFile(file_name, destination_path);
         if(!delete_file(file_name)){
	       printf("Error deleting temp file");
	       fclose(file);
	 }

	 if (fclose(file) == EOF) {
    		printf("Error closing file");
	} 

	 flag_new_file = true;
    }else{
	 flag_new_file = false;
    }*/
   

}

void socket_handle(struct event *e)
{
        int state;

        if(e->conn_passive == 1){
	     write_tuples(e);
         }

	state = e->newstate;
	if(state == TCP_ESTABLISHED){
	    write_tuples(e);
	}
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct event *e = data;
        socket_handle(e);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	printf("lost events on CPU");
}

/*static void findAndReplace(char *original, const char *find, const char *replace) {
           char *start = original;
           size_t findLen = strlen(find);
           size_t replaceLen = strlen(replace);

           while ((start = strstr(start, find)) != NULL) {
               memmove(start + replaceLen, start + findLen, strlen(start + findLen) + 1);
               memcpy(start, replace, replaceLen);
               start += replaceLen;
           }
}*/

char abs_exe_path[300];

int main(int argc, char **argv)
{
	char path_save[PATH_MAX];
  	char *p;
        struct perf_buffer *pb = NULL;
        struct tcpretrans_bpf *obj;
        int err;
	struct stat st = {0};
        printf("starting \n");

	LIBBPF_OPTS(bpf_object_open_opts, open_opts);

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		return 1;
	}
	obj = tcpretrans_bpf__open_opts(&open_opts);
	if (!obj) {
		return 1;
	}else{
	}


	err = tcpretrans_bpf__load(obj);
	if (err) {
		goto cleanup;
	} else {
	}


	err = tcpretrans_bpf__attach(obj);
	if (err) {
		goto cleanup;
	} else {
	}

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = - errno;
                printf("failed to open perf buffer");
		goto cleanup;
	} else {
		printf("Opening perf buffer successful");
	}

	if ((signal(SIGINT, sig_int) == SIG_ERR) || (signal(SIGTERM, sig_int) == SIG_ERR) || 
			(signal(SIGTSTP, sig_int) == SIG_ERR) || (signal(SIGSEGV, sig_int) == SIG_ERR) || (signal(SIGUSR1, sig_int) == SIG_ERR)){
		printf("can't set signal handler");
		err = 1;
		goto cleanup;
	}
        isFiveMinutesPassed();
        printf("hello");
	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			printf("error polling perf buffer");

			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	tcpretrans_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);
	remove_lock_file();
        printf("Cleaning up buffers and BTF");
	printf("Removing lock file");
	return err != 0;
}
