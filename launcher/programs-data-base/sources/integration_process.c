/*
 * integration_process_healthcare_cheri.c
 *
 * Description:
 *   This program implements the Integration Process described in the healthcare
 *   pilot scenario. The process executes in a CHERI-based trusted
 *   execution environment and coordinates three digital services:
 *
 *     (i)  HealthRegistryService  - source of patient records
 *     (ii) HospitalService        - target service for attendance synchronisation
 *     (iii) MessagingService      - patient notification service
 *
 *   The implementation follows, in a simplified manner:
 *
 *     - Launcher:
 *         generates the attestation certificate and retrieves the certificate
 *         associated with the deployed program;
 *
 *     - Program:
 *         represents the executable currently deployed in the CHERI environment;
 *
 *     - IntegrationProcess:
 *         orchestrates read and write operations across digital services;
 *
 *     - DigitalService:
 *         represents a remote application that validates the attested execution
 *         environment before processing a request.
 *
 * Security and attestation model:
 *   Every outgoing GET or POST request includes an attestation certificate
 *   associated with the execution environment of the Integration Process.
 *   Digital services are expected to validate this certificate before performing
 *   operations over sensitive data.
 *
 * Confidential deployment strategy:
 *   Network addresses and ports of digital services are not hardcoded in the
 *   implementation. Instead, they are loaded from environment variables, thus
 *   avoiding direct disclosure of infrastructure details in the source code.
 *
 * Compilation (Arm Morello / CHERI):
 *   clang-morello -march=morello+c64 -mabi=purecap -g \
 *     -o integration_process_healthcare_cheri integration_process_healthcare_cheri.c \
 *     -lssl -lcrypto -lpthread
 *
 * Execution with CHERI compartmentalisation:
 *   proccontrol -m cheric18n -s enable ./integration_process_healthcare_cheri
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <dirent.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* -------------------------------------------------------------------------- */
/*                          Paths managed by the Launcher                      */
/* -------------------------------------------------------------------------- */

#define LAUNCHER_BASE_DIR "../tee-compartmentalisation-study-case/launcher"
#define EXECUTABLES_DIR   LAUNCHER_BASE_DIR "/programs-data-base/cheri-caps-executables"
#define CERTIFICATES_DIR  LAUNCHER_BASE_DIR "/programs-data-base/certificates"
#define GENERATOR_SCRIPT  LAUNCHER_BASE_DIR "/attestable-data/generate_certificate.py"

#define TLS_CERT_FILE LAUNCHER_BASE_DIR "/keys/cert.pem"
#define TLS_KEY_FILE  LAUNCHER_BASE_DIR "/keys/prk.pem"

#define DEFAULT_PATIENT_ID "12345678900"

/* -------------------------------------------------------------------------- */
/*                  Default values used only when env vars are absent          */
/* -------------------------------------------------------------------------- */

#define DEFAULT_HEALTH_REGISTRY_HOST     "200.xxx.xxx.xxx"
#define DEFAULT_HEALTH_REGISTRY_PORT     "8443"
#define DEFAULT_HEALTH_REGISTRY_ENDPOINT "/api/patients"

#define DEFAULT_HOSPITAL_HOST            "200.xxx.xxx.xxx"
#define DEFAULT_HOSPITAL_PORT            "8443"
#define DEFAULT_HOSPITAL_ENDPOINT        "/api/attendances/sync"

#define DEFAULT_MESSAGING_HOST           "200.xxx.xxx.xxx
#define DEFAULT_MESSAGING_PORT           "8443"
#define DEFAULT_MESSAGING_ENDPOINT       "/api/notifications"

/* -------------------------------------------------------------------------- */
/*                             Conceptual entities                             */
/* -------------------------------------------------------------------------- */

/*
 * Program:
 *   Represents the executable currently deployed in the CHERI-enabled execution
 *   environment. Its identifier, code path, and certificate path are recovered
 *   dynamically by the Launcher.
 */
typedef struct {
    char id[PATH_MAX];
    char codePath[PATH_MAX];
    char certificatePath[PATH_MAX];
} Program;

/*
 * DigitalService:
 *   Represents a remote application that receives requests from the
 *   IntegrationProcess. Each service is expected to validate the attestation
 *   certificate before processing sensitive operations.
 */
typedef struct {
    char name[64];
    char host[128];
    char port[16];
    char readEndpoint[128];
    char writeEndpoint[128];
} DigitalService;

/*
 * Launcher:
 *   Encapsulates certificate generation and recovery of the current program
 *   metadata. In the conceptual model, it acts as the mediating component
 *   between the CHERI execution environment and external digital services.
 */
typedef struct {
    Program program;
} Launcher;

/*
 * IntegrationProcess:
 *   Coordinates read and write operations among remote digital services while
 *   running inside a CHERI-based trusted execution environment.
 */
typedef struct {
    Launcher *launcher;
    DigitalService healthRegistryService;
    DigitalService hospitalService;
    DigitalService messagingService;
} IntegrationProcess;

/* -------------------------------------------------------------------------- */
/*                         Synchronisation / Launcher state                    */
/* -------------------------------------------------------------------------- */

static pthread_mutex_t certificateMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t certificateCond = PTHREAD_COND_INITIALIZER;
static int certificateReady = 0;

/* -------------------------------------------------------------------------- */
/*                           Configuration utilities                           */
/* -------------------------------------------------------------------------- */

/*
 * loadConfigValue:
 *   Loads a configuration value from an environment variable. If the variable
 *   is not defined, the provided default value is used.
 */
static void loadConfigValue(const char *envName,
                            const char *defaultValue,
                            char *target,
                            size_t targetSize) {
    const char *value = getenv(envName);

    if (value && strlen(value) > 0) {
        strncpy(target, value, targetSize - 1);
    } else {
        strncpy(target, defaultValue, targetSize - 1);
    }

    target[targetSize - 1] = '\0';
}

/* -------------------------------------------------------------------------- */
/*                               SSL utilities                                 */
/* -------------------------------------------------------------------------- */

static void cleanupSsl(SSL *ssl, SSL_CTX *ctx) {
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }

    if (ctx) {
        SSL_CTX_free(ctx);
    }

    ERR_free_strings();
    EVP_cleanup();
}

static SSL_CTX *initializeSslContext(void) {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    method = TLS_client_method();
    ctx = SSL_CTX_new(method);

    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    if (SSL_CTX_use_certificate_file(ctx, TLS_CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, TLS_KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

/*
 * tlsHttpRequest:
 *   Opens a TLS connection to the target digital service, sends the prepared
 *   HTTP request, and returns the full HTTP response as a dynamically allocated
 *   buffer.
 */
static int tlsHttpRequest(const char *host,
                          const char *port,
                          const char *request,
                          char **responseOut) {
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int server = -1;
    int status = -1;
    struct sockaddr_in serverAddr;
    char buffer[4096];
    ssize_t n;
    size_t total = 0;
    char *response = NULL;

    *responseOut = NULL;

    ctx = initializeSslContext();
    if (!ctx) goto cleanup;

    server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) {
        perror("socket");
        goto cleanup;
    }

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons((unsigned short)atoi(port));

    if (inet_pton(AF_INET, host, &serverAddr.sin_addr) <= 0) {
        perror("inet_pton");
        goto cleanup;
    }

    if (connect(server, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("connect");
        goto cleanup;
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    if (SSL_write(ssl, request, (int)strlen(request)) <= 0) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    while ((n = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
        char *tmp;
        buffer[n] = '\0';

        tmp = realloc(response, total + (size_t)n + 1);
        if (!tmp) {
            fprintf(stderr, "Memory allocation error while receiving HTTPS response.\n");
            free(response);
            response = NULL;
            goto cleanup;
        }

        response = tmp;
        memcpy(response + total, buffer, (size_t)n);
        total += (size_t)n;
        response[total] = '\0';
    }

    if (n < 0) {
        perror("SSL_read");
        free(response);
        response = NULL;
        goto cleanup;
    }

    *responseOut = response;
    status = 0;

cleanup:
    if (server >= 0) {
        close(server);
    }
    cleanupSsl(ssl, ctx);
    return status;
}

/* -------------------------------------------------------------------------- */
/*                         Program / Launcher utilities                        */
/* -------------------------------------------------------------------------- */

/*
 * readFileStripNewlines:
 *   Reads a file into memory and removes line breaks. This is useful when the
 *   certificate needs to be embedded in a single HTTP header line.
 */
static char *readFileStripNewlines(const char *path) {
    FILE *fp = fopen(path, "rb");
    long size;
    char *raw = NULL;
    char *clean = NULL;
    size_t i, j = 0;

    if (!fp) {
        perror("fopen");
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    rewind(fp);

    raw = (char *)malloc((size_t)size + 1);
    if (!raw) {
        fclose(fp);
        return NULL;
    }

    if (fread(raw, 1, (size_t)size, fp) != (size_t)size) {
        fclose(fp);
        free(raw);
        return NULL;
    }

    fclose(fp);
    raw[size] = '\0';

    clean = (char *)malloc((size_t)size + 1);
    if (!clean) {
        free(raw);
        return NULL;
    }

    for (i = 0; i < (size_t)size; ++i) {
        if (raw[i] != '\n' && raw[i] != '\r') {
            clean[j++] = raw[i];
        }
    }

    clean[j] = '\0';
    free(raw);
    return clean;
}

/*
 * launcherGetProgram:
 *   Recovers the most recent CHERI executable and derives the path to the
 *   certificate generated for that program.
 */
static int launcherGetProgram(Launcher *launcher) {
    DIR *dir;
    struct dirent *entry;
    time_t latestTime = 0;
    char latestName[PATH_MAX] = {0};

    dir = opendir(EXECUTABLES_DIR);
    if (!dir) {
        perror("opendir");
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        char fullPath[PATH_MAX];
        struct stat st;

        if (strncmp(entry->d_name, "integration_process", 19) != 0) {
            continue;
        }

        snprintf(fullPath, sizeof(fullPath), "%s/%s", EXECUTABLES_DIR, entry->d_name);

        if (stat(fullPath, &st) == 0 && st.st_ctime > latestTime) {
            latestTime = st.st_ctime;
            strncpy(latestName, entry->d_name, sizeof(latestName) - 1);
        }
    }

    closedir(dir);

    if (latestName[0] == '\0') {
        fprintf(stderr, "No CHERI executable found in %s\n", EXECUTABLES_DIR);
        return -1;
    }

    strncpy(launcher->program.id, latestName, sizeof(launcher->program.id) - 1);

    snprintf(launcher->program.codePath,
             sizeof(launcher->program.codePath),
             "%s/%s",
             EXECUTABLES_DIR,
             latestName);

    snprintf(launcher->program.certificatePath,
             sizeof(launcher->program.certificatePath),
             "%s/%s/certificate.pem",
             CERTIFICATES_DIR,
             latestName);

    return 0;
}

/*
 * launcherGenerateCertificate:
 *   Invokes the certificate generation script responsible for collecting
 *   attestable execution metadata and producing the program certificate.
 */
static int launcherGenerateCertificate(Launcher *launcher, pid_t pid) {
    char command[1024];
    (void)launcher;

    snprintf(command, sizeof(command), "python3 %s %d", GENERATOR_SCRIPT, pid);

    if (system(command) != 0) {
        fprintf(stderr, "Certificate generation failed.\n");
        return -1;
    }

    return 0;
}

/*
 * launcherGetCertificate:
 *   Recovers the certificate associated with the latest deployed program.
 */
static char *launcherGetCertificate(Launcher *launcher) {
    if (launcherGetProgram(launcher) != 0) {
        return NULL;
    }

    return readFileStripNewlines(launcher->program.certificatePath);
}

/*
 * buildGetRequestWithCertificate:
 *   Builds an HTTPS GET request including the attestation certificate in the
 *   request header.
 */
static int buildGetRequestWithCertificate(Launcher *launcher,
                                          const DigitalService *service,
                                          const char *endpointWithQuery,
                                          char **requestOut) {
    char *certificate = launcherGetCertificate(launcher);
    char *request;
    size_t needed;

    *requestOut = NULL;

    if (!certificate) {
        fprintf(stderr, "Could not load attestation certificate.\n");
        return -1;
    }

    needed = snprintf(NULL, 0,
                      "GET %s HTTP/1.1\r\n"
                      "Host: %s\r\n"
                      "Accept: application/json\r\n"
                      "X-Attestation-Cert: %s\r\n"
                      "Connection: close\r\n\r\n",
                      endpointWithQuery,
                      service->host,
                      certificate) + 1;

    request = (char *)malloc(needed);
    if (!request) {
        free(certificate);
        return -1;
    }

    snprintf(request, needed,
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Accept: application/json\r\n"
             "X-Attestation-Cert: %s\r\n"
             "Connection: close\r\n\r\n",
             endpointWithQuery,
             service->host,
             certificate);

    free(certificate);
    *requestOut = request;
    return 0;
}

/*
 * buildPostRequestWithCertificate:
 *   Builds an HTTPS POST request including the attestation certificate in the
 *   request header.
 */
static int buildPostRequestWithCertificate(Launcher *launcher,
                                           const DigitalService *service,
                                           const char *endpoint,
                                           const char *jsonPayload,
                                           char **requestOut) {
    char *certificate = launcherGetCertificate(launcher);
    char *request;
    size_t needed;

    *requestOut = NULL;

    if (!certificate) {
        fprintf(stderr, "Could not load attestation certificate.\n");
        return -1;
    }

    needed = snprintf(NULL, 0,
                      "POST %s HTTP/1.1\r\n"
                      "Host: %s\r\n"
                      "Content-Type: application/json\r\n"
                      "Accept: application/json\r\n"
                      "X-Attestation-Cert: %s\r\n"
                      "Content-Length: %zu\r\n"
                      "Connection: close\r\n\r\n"
                      "%s",
                      endpoint,
                      service->host,
                      certificate,
                      strlen(jsonPayload),
                      jsonPayload) + 1;

    request = (char *)malloc(needed);
    if (!request) {
        free(certificate);
        return -1;
    }

    snprintf(request, needed,
             "POST %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Content-Type: application/json\r\n"
             "Accept: application/json\r\n"
             "X-Attestation-Cert: %s\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n\r\n"
             "%s",
             endpoint,
             service->host,
             certificate,
             strlen(jsonPayload),
             jsonPayload);

    free(certificate);
    *requestOut = request;
    return 0;
}

/* -------------------------------------------------------------------------- */
/*                         HTTP / JSON helper utilities                        */
/* -------------------------------------------------------------------------- */

/*
 * extractHttpBody:
 *   Extracts the body portion of a raw HTTP response.
 */
static char *extractHttpBody(const char *httpResponse) {
    const char *body = strstr(httpResponse, "\r\n\r\n");
    if (!body) {
        return NULL;
    }
    return strdup(body + 4);
}

/*
 * extractJsonStringField:
 *   Extracts a simple JSON string field using basic string matching. This
 *   function is intentionally lightweight for the pilot implementation.
 */
static char *extractJsonStringField(const char *json, const char *fieldName) {
    char pattern[128];
    const char *start;
    const char *end;
    char *value;
    size_t len;

    snprintf(pattern, sizeof(pattern), "\"%s\":\"", fieldName);
    start = strstr(json, pattern);

    if (!start) {
        snprintf(pattern, sizeof(pattern), "\"%s\": \"", fieldName);
        start = strstr(json, pattern);
        if (!start) {
            return NULL;
        }
    }

    start += strlen(pattern);
    end = strchr(start, '"');
    if (!end) {
        return NULL;
    }

    len = (size_t)(end - start);
    value = (char *)malloc(len + 1);
    if (!value) {
        return NULL;
    }

    strncpy(value, start, len);
    value[len] = '\0';
    return value;
}

/* -------------------------------------------------------------------------- */
/*                    IntegrationProcess service operations                    */
/* -------------------------------------------------------------------------- */

/*
 * integrationProcessRead:
 *   Reads patient data from the HealthRegistryService using an attested GET
 *   request.
 */
static int integrationProcessRead(IntegrationProcess *integrationProcess,
                                  const char *patientId,
                                  char **patientJson) {
    char endpointWithQuery[512];
    char *request = NULL;
    char *response = NULL;
    char *body = NULL;

    *patientJson = NULL;

    snprintf(endpointWithQuery,
             sizeof(endpointWithQuery),
             "%s?patient_id=%s",
             integrationProcess->healthRegistryService.readEndpoint,
             patientId);

    if (buildGetRequestWithCertificate(integrationProcess->launcher,
                                       &integrationProcess->healthRegistryService,
                                       endpointWithQuery,
                                       &request) != 0) {
        fprintf(stderr, "Failed to build attested GET request for HealthRegistryService.\n");
        return -1;
    }

    if (tlsHttpRequest(integrationProcess->healthRegistryService.host,
                       integrationProcess->healthRegistryService.port,
                       request,
                       &response) != 0) {
        fprintf(stderr, "Failed to retrieve patient data from HealthRegistryService.\n");
        free(request);
        return -1;
    }

    free(request);

    body = extractHttpBody(response);
    free(response);

    if (!body) {
        fprintf(stderr, "Failed to extract HTTP body from HealthRegistryService response.\n");
        return -1;
    }

    *patientJson = body;
    return 0;
}

/*
 * integrationProcessWriteHospital:
 *   Sends patient data to the HospitalService using an attested POST request.
 */
static int integrationProcessWriteHospital(IntegrationProcess *integrationProcess,
                                           const char *patientJson) {
    char *request = NULL;
    char *response = NULL;

    if (buildPostRequestWithCertificate(integrationProcess->launcher,
                                        &integrationProcess->hospitalService,
                                        integrationProcess->hospitalService.writeEndpoint,
                                        patientJson,
                                        &request) != 0) {
        fprintf(stderr, "Failed to build attested POST request for HospitalService.\n");
        return -1;
    }

    if (tlsHttpRequest(integrationProcess->hospitalService.host,
                       integrationProcess->hospitalService.port,
                       request,
                       &response) != 0) {
        fprintf(stderr, "Failed to send patient data to HospitalService.\n");
        free(request);
        return -1;
    }

    printf("HospitalService response:\n%s\n", response);

    free(request);
    free(response);
    return 0;
}

/*
 * integrationProcessWriteMessaging:
 *   Sends a patient notification through the MessagingService using an attested
 *   POST request.
 */
static int integrationProcessWriteMessaging(IntegrationProcess *integrationProcess,
                                            const char *patientJson) {
    char *name = NULL;
    char *phone = NULL;
    char payload[2048];
    char *request = NULL;
    char *response = NULL;
    int status = -1;

    name = extractJsonStringField(patientJson, "name");
    if (!name) {
        name = extractJsonStringField(patientJson, "nome");
    }

    phone = extractJsonStringField(patientJson, "phone");
    if (!phone) {
        phone = extractJsonStringField(patientJson, "telefone");
    }

    if (!name) {
        name = strdup("patient");
    }

    if (!phone) {
        fprintf(stderr, "Could not extract patient phone number from retrieved data.\n");
        goto cleanup;
    }

    snprintf(payload, sizeof(payload),
             "{\"numero_telefone\":\"%s\","
             "\"mensagem\":\"Dear %s, your attendance data were synchronised successfully.\"}",
             phone, name);

    if (buildPostRequestWithCertificate(integrationProcess->launcher,
                                        &integrationProcess->messagingService,
                                        integrationProcess->messagingService.writeEndpoint,
                                        payload,
                                        &request) != 0) {
        fprintf(stderr, "Failed to build attested POST request for MessagingService.\n");
        goto cleanup;
    }

    if (tlsHttpRequest(integrationProcess->messagingService.host,
                       integrationProcess->messagingService.port,
                       request,
                       &response) != 0) {
        fprintf(stderr, "Failed to send patient notification through MessagingService.\n");
        goto cleanup;
    }

    printf("MessagingService response:\n%s\n", response);
    status = 0;

cleanup:
    free(name);
    free(phone);
    free(request);
    free(response);
    return status;
}

/*
 * integrationProcessRun:
 *   Executes the orchestration logic of the pilot scenario:
 *     1) read patient data from HealthRegistryService
 *     2) write synchronised data to HospitalService
 *     3) notify the patient through MessagingService
 */
static int integrationProcessRun(IntegrationProcess *integrationProcess,
                                 const char *patientId) {
    char *patientJson = NULL;
    int status = -1;

    if (integrationProcessRead(integrationProcess, patientId, &patientJson) != 0) {
        fprintf(stderr, "Integration step failed: could not read patient data.\n");
        goto cleanup;
    }

    printf("Patient data retrieved from HealthRegistryService:\n%s\n", patientJson);

    if (integrationProcessWriteHospital(integrationProcess, patientJson) != 0) {
        fprintf(stderr, "Integration step failed: could not synchronise HospitalService.\n");
        goto cleanup;
    }

    if (integrationProcessWriteMessaging(integrationProcess, patientJson) != 0) {
        fprintf(stderr, "Integration step failed: could not notify patient.\n");
        goto cleanup;
    }

    status = 0;

cleanup:
    free(patientJson);
    return status;
}

/* -------------------------------------------------------------------------- */
/*                         Launcher initialisation thread                      */
/* -------------------------------------------------------------------------- */

/*
 * launcherThread:
 *   Generates the certificate associated with the running process before the
 *   integration workflow starts.
 */
static void *launcherThread(void *arg) {
    Launcher *launcher = (Launcher *)arg;

    if (launcherGenerateCertificate(launcher, getpid()) != 0) {
        pthread_exit((void *)1);
    }

    pthread_mutex_lock(&certificateMutex);
    certificateReady = 1;
    pthread_cond_signal(&certificateCond);
    pthread_mutex_unlock(&certificateMutex);

    return NULL;
}

/* -------------------------------------------------------------------------- */
/*                                   Main                                     */
/* -------------------------------------------------------------------------- */

int main(int argc, char *argv[]) {
    Launcher launcher;
    IntegrationProcess integrationProcess;
    pthread_t launcherWorker;
    const char *patientId = DEFAULT_PATIENT_ID;

    memset(&launcher, 0, sizeof(launcher));
    memset(&integrationProcess, 0, sizeof(integrationProcess));

    if (argc > 1) {
        patientId = argv[1];
    }

    integrationProcess.launcher = &launcher;

    strncpy(integrationProcess.healthRegistryService.name,
            "HealthRegistryService",
            sizeof(integrationProcess.healthRegistryService.name) - 1);
    loadConfigValue("HEALTH_REGISTRY_HOST",
                    DEFAULT_HEALTH_REGISTRY_HOST,
                    integrationProcess.healthRegistryService.host,
                    sizeof(integrationProcess.healthRegistryService.host));
    loadConfigValue("HEALTH_REGISTRY_PORT",
                    DEFAULT_HEALTH_REGISTRY_PORT,
                    integrationProcess.healthRegistryService.port,
                    sizeof(integrationProcess.healthRegistryService.port));
    loadConfigValue("HEALTH_REGISTRY_ENDPOINT",
                    DEFAULT_HEALTH_REGISTRY_ENDPOINT,
                    integrationProcess.healthRegistryService.readEndpoint,
                    sizeof(integrationProcess.healthRegistryService.readEndpoint));

    strncpy(integrationProcess.hospitalService.name,
            "HospitalService",
            sizeof(integrationProcess.hospitalService.name) - 1);
    loadConfigValue("HOSPITAL_HOST",
                    DEFAULT_HOSPITAL_HOST,
                    integrationProcess.hospitalService.host,
                    sizeof(integrationProcess.hospitalService.host));
    loadConfigValue("HOSPITAL_PORT",
                    DEFAULT_HOSPITAL_PORT,
                    integrationProcess.hospitalService.port,
                    sizeof(integrationProcess.hospitalService.port));
    loadConfigValue("HOSPITAL_ENDPOINT",
                    DEFAULT_HOSPITAL_ENDPOINT,
                    integrationProcess.hospitalService.writeEndpoint,
                    sizeof(integrationProcess.hospitalService.writeEndpoint));

    strncpy(integrationProcess.messagingService.name,
            "MessagingService",
            sizeof(integrationProcess.messagingService.name) - 1);
    loadConfigValue("MESSAGING_HOST",
                    DEFAULT_MESSAGING_HOST,
                    integrationProcess.messagingService.host,
                    sizeof(integrationProcess.messagingService.host));
    loadConfigValue("MESSAGING_PORT",
                    DEFAULT_MESSAGING_PORT,
                    integrationProcess.messagingService.port,
                    sizeof(integrationProcess.messagingService.port));
    loadConfigValue("MESSAGING_ENDPOINT",
                    DEFAULT_MESSAGING_ENDPOINT,
                    integrationProcess.messagingService.writeEndpoint,
                    sizeof(integrationProcess.messagingService.writeEndpoint));

    if (pthread_create(&launcherWorker, NULL, launcherThread, &launcher) != 0) {
        fprintf(stderr, "Could not create Launcher thread.\n");
        return 1;
    }

    pthread_mutex_lock(&certificateMutex);
    while (!certificateReady) {
        pthread_cond_wait(&certificateCond, &certificateMutex);
    }
    pthread_mutex_unlock(&certificateMutex);

    if (integrationProcessRun(&integrationProcess, patientId) != 0) {
        fprintf(stderr, "Integration process failed.\n");
        pthread_join(launcherWorker, NULL);
        return 1;
    }

    pthread_join(launcherWorker, NULL);
    return 0;
}