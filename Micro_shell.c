#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <fcntl.h>

#define p(...) printf(__VA_ARGS__)
#define DEL "\n\t \v\f\r"
#define CELL_JR 0

int status = 0;
char *redir_in = NULL;   // Filename for < (stdin)
char *redir_out = NULL;  // Filename for > (stdout)
char *redir_err = NULL;  // Filename for 2> (stderr)

typedef struct s_builtin {
    const char *builtin_name;
    int (*foo)(char **);
} t_builtin;

int cell_echo(char **args)
{
    int start = 1;
    bool newline = true;

    if (!args || !args[0])
        return 1;

    if (args[1] && !strcmp(args[1], "-n")) {
        newline = false;
        start = 2;
    }

    for (int i = start; args[i]; i++) {
        p("%s", args[i]);
        if (args[i + 1])
            p(" ");
    }

    if (newline)
        p("\n");

    return 0;
}

int cell_env(char **args)
{
    extern char **environ;
    (void)args;
    if (!environ)
        return 1;
    for (int i = 0; environ[i]; i++)
        p("%s\n", environ[i]);
    return 0;
}

int cell_exit(char **args)
{
    (void)args;
    exit(EX_OK);
}

int cell_export(char **args)
{
    if (!args[1]) {
        extern char **environ;
        if (!environ)
            return 1;
        for (int i = 0; environ[i]; i++) {
            p("%s\n", environ[i]);
        }
        return 0;
    }

    char *arg = args[1];
    char *name = arg;
    char *value = NULL;

    char *equal_sign = strchr(arg, '=');
    if (equal_sign) {
        *equal_sign = '\0';
        value = equal_sign + 1;
        if (!*name || !*value) {
            p("export: invalid format '%s'\n", arg);
            return 1;
        }
    } else {
        if (!getenv(name)) {
            p("export: variable '%s' not found\n", name);
            return 1;
        }
        return 0;
    }

    if (setenv(name, value, 1) == -1) {
        perror("setenv failed");
        return 1;
    }

    return 0;
}

t_builtin g_builtin[] = {
    {"echo", cell_echo},
    {"env", cell_env},
    {"exit", cell_exit},
    {"export", cell_export},
    {NULL, NULL}
};

pid_t Fork(void)
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("Fork failed");
        exit(EX_OSERR);
    }
    return pid;
}

void Execvp(const char *file, char *const argv[])
{
    if (!file || !argv) {
        fprintf(stderr, "Execvp: invalid arguments\n");
        exit(EXIT_FAILURE);
    }
    if (execvp(file, argv) == -1) {
        perror("CELL_Jr failed");
        exit(EX_UNAVAILABLE);
    }
}

pid_t Wait(int *status)
{
    pid_t result;
    if (!status) {
        fprintf(stderr, "Wait: status argument required\n");
        return -1;
    }
    result = wait(status);
    if (result == -1)
        perror("Wait failed");
    if (WIFEXITED(*status))
        *status = WEXITSTATUS(*status);
    return result;
}

void *Malloc(size_t size)
{
    if (size == 0)
        return NULL;
    void *ptr = malloc(size);
    if (!ptr) {
        perror("Malloc failed");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

void *Realloc(void *ptr, size_t size)
{
    void *new_ptr = realloc(ptr, size);
    if (!new_ptr && size != 0) {
        perror("Realloc failed");
        exit(EXIT_FAILURE);
    }
    return new_ptr;
}

char *strdup(const char *s)
{
    size_t len = strlen(s) + 1;
    char *new = Malloc(len);
    memcpy(new, s, len);
    return new;
}

char *cell_read_line(void)
{
    char *buf = NULL;
    size_t bufSize = 0;
    char cwd[BUFSIZ];

    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        perror("getcwd failed");
    } else {
        printf("%s>> ", cwd);
    }

    ssize_t read = getline(&buf, &bufSize, stdin);
    if (read == -1) {
        if (feof(stdin)) {
            printf("[EOF]\n");
            free(buf);
            exit(EXIT_SUCCESS);
        } else {
            perror("getline failed");
            free(buf);
            exit(EXIT_FAILURE);
        }
    }

    if (read > 0 && buf[read - 1] == '\n') {
        buf[read - 1] = '\0';
    }

    return buf;
}

char **cell_split_line(char *line)
{
    free(redir_in);
    free(redir_out);
    free(redir_err);
    redir_in = NULL;
    redir_out = NULL;
    redir_err = NULL;

    if (!line) {
        char **tokens = Malloc(sizeof(*tokens));
        tokens[0] = NULL;
        return tokens;
    }

    char **tokens = Malloc(BUFSIZ * sizeof(*tokens));
    size_t bufsize = BUFSIZ;
    unsigned int position = 0;

    char *token = strtok(line, DEL);
    while (token) {
        if (strcmp(token, "<") == 0) {
            token = strtok(NULL, DEL);
            if (!token) {
                p("syntax error: missing filename after '<'\n");
                for (unsigned int i = 0; i < position; i++) {
                    free(tokens[i]);
                }
                free(tokens);
                return NULL;
            }
            redir_in = strdup(token);
            if (!redir_in) {
                perror("strdup failed");
                exit(EXIT_FAILURE);
            }
        } else if (strcmp(token, ">") == 0) {
            token = strtok(NULL, DEL);
            if (!token) {
                p("syntax error: missing filename after '>'\n");
                for (unsigned int i = 0; i < position; i++) {
                    free(tokens[i]);
                }
                free(tokens);
                return NULL;
            }
            redir_out = strdup(token);
            if (!redir_out) {
                perror("strdup failed");
                exit(EXIT_FAILURE);
            }
        } else if (strcmp(token, "2>") == 0) {
            token = strtok(NULL, DEL);
            if (!token) {
                p("syntax error: missing filename after '2>'\n");
                for (unsigned int i = 0; i < position; i++) {
                    free(tokens[i]);
                }
                free(tokens);
                return NULL;
            }
            redir_err = strdup(token);
            if (!redir_err) {
                perror("strdup failed");
                exit(EXIT_FAILURE);
            }
        } else {
            tokens[position] = strdup(token);
            if (!tokens[position]) {
                perror("strdup failed");
                exit(EXIT_FAILURE);
            }
            position++;
            if (position >= bufsize) {
                bufsize *= 2;
                tokens = Realloc(tokens, bufsize * sizeof(*tokens));
            }
        }
        token = strtok(NULL, DEL);
    }
    tokens[position] = NULL;

    return tokens;
}

void cell_launch(char **args)
{
    if (!args || !args[0]) {
        return;
    }

    pid_t pid = Fork();
    if (pid == CELL_JR) {
        if (redir_in) {
            int fd = open(redir_in, O_RDONLY);
            if (fd == -1) {
                perror(redir_in);
                exit(EXIT_FAILURE);
            }
            if (dup2(fd, STDIN_FILENO) == -1) {
                perror("dup2 failed");
                exit(EXIT_FAILURE);
            }
            close(fd);
        }

        if (redir_out) {
            int fd = open(redir_out, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd == -1) {
                perror(redir_out);
                exit(EXIT_FAILURE);
            }
            if (dup2(fd, STDOUT_FILENO) == -1) {
                perror("dup2 failed");
                exit(EXIT_FAILURE);
            }
            close(fd);
        }

        if (redir_err) {
            int fd = open(redir_err, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd == -1) {
                perror(redir_err);
                exit(EXIT_FAILURE);
            }
            if (dup2(fd, STDERR_FILENO) == -1) {
                perror("dup2 failed");
                exit(EXIT_FAILURE);
            }
            close(fd);
        }

        Execvp(args[0], args);
    } else {
        Wait(&status);
    }
}

void cell_execute(char **args)
{
    if (!args || !args[0])
        return;

    for (int i = 0; g_builtin[i].builtin_name; i++) {
        if (!strcmp(args[0], g_builtin[i].builtin_name)) {
            status = g_builtin[i].foo(args);
            if (status)
                p("%s failed\n", g_builtin[i].builtin_name);
            return;
        }
    }
    cell_launch(args);
}

int main(void)
{
    while (1) {
        char *line = cell_read_line();
        char **args = cell_split_line(line);
        if (args) {
            for (int i = 0; args[i]; i++) {
                p("%s\n", args[i]);
            }
            cell_execute(args);

            for (int i = 0; args[i]; i++) {
                free(args[i]);
            }
            free(args);
        }
        free(redir_in);
        free(redir_out);
        free(redir_err);
        redir_in = NULL;
        redir_out = NULL;
        redir_err = NULL;
        free(line);
    }
    return 0;
}
