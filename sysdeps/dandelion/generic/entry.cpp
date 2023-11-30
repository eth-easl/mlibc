#include <bits/ensure.h>
#include <dandelion/runtime.h>
#include <mlibc/elf/startup.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <filesystem.hpp>

// defined by the POSIX library
void __mlibc_initLocale();

extern "C" uintptr_t *__dlapi_entrystack();
extern "C" void __dlapi_enter(uintptr_t *);

extern char **environ;
static mlibc::exec_stack_data __mlibc_stack_data;

struct LibraryGuard {
  LibraryGuard();
};

static LibraryGuard guard;

LibraryGuard::LibraryGuard() {
  __mlibc_initLocale();

  // Parse the exec() stack.
  mlibc::parse_exec_stack(__dlapi_entrystack(), &__mlibc_stack_data);
  mlibc::set_startup_data(__mlibc_stack_data.argc, __mlibc_stack_data.argv,
                          __mlibc_stack_data.envp);
}

char **setup_charpparray(struct io_buffer *buffer, int *count) {
  if (buffer != NULL) {
    // count every non empy string (at least one character followed by 0
    size_t string_count = 0;
    uint8_t had_char = 0;
    size_t max_length = buffer->data_len;
    char *string_buffer = (char *)buffer->data;
    for (size_t iter = 0; iter < max_length; iter++) {
      // detect if this is the end of a string
      if (string_buffer[iter] == 0 && had_char) {
        string_count++;
        had_char = 0;
      } else if (string_buffer[iter] != 0) {
        had_char = 1;
      }
    }
    if (string_count == 0) {
      *count = 0;
      return NULL;
    }
    // argc does not include the terminating NULL pointer of the array
    // we expect the name to be included in the argv item buffer
    char **pointer_buffer = (char **)dandelion_alloc(
        sizeof(char *) * (string_count + 1), sizeof(char *));
    had_char = 0;
    string_count = 0;
    char *string_start = NULL;
    for (size_t iter = 0; iter < max_length; iter++) {
      if (string_buffer[iter] != 0 && !had_char) {
        string_start = &string_buffer[iter];
        had_char = 1;
      } else if (string_buffer[iter] == 0 && had_char) {
        had_char = 0;
        pointer_buffer[string_count] = string_start;
        string_count++;
      }
    }
    *count = string_count;
    return pointer_buffer;
  } else {
    *count = 0;
    return NULL;
  }
}

void setup_stack_data(size_t set_index) {
  // find argv item
  const char *const argv_string = "argv";
  char const *const env_string = "environ";
  // remove one for C terminating NUL character
  const size_t argv_length = sizeof("argv") - 1;
  const size_t environ_length = sizeof("environ") - 1;
  size_t item_number = dandelion_input_buffer_count(set_index);
  struct io_buffer *argv_buffer = NULL;
  struct io_buffer *environ_buffer = NULL;
  for (size_t item_index = 0; item_index < item_number; item_index++) {
    struct io_buffer *item_buffer = dandelion_get_input(set_index, item_index);
    if (item_buffer == NULL || item_buffer->ident_len == 0 ||
        item_buffer->ident == NULL)
      continue;
    if (argv_length == item_buffer->ident_len &&
        !strncmp(argv_string, item_buffer->ident, argv_length)) {
      argv_buffer = item_buffer;
    } else if (environ_length == item_buffer->ident_len &&
               !strncmp(env_string, item_buffer->ident, environ_length)) {
      environ_buffer = item_buffer;
    }
  }
  __mlibc_stack_data.argv =
      setup_charpparray(argv_buffer, &__mlibc_stack_data.argc);
  int environ_count = 0;
  environ = setup_charpparray(environ_buffer, &environ_count);
}

extern "C" void __mlibc_entry(uintptr_t *entry_stack,
                              int (*main_fn)(int argc, char *argv[],
                                             char *env[])) {
  dandelion_init();
  __dlapi_enter(entry_stack);
  // find stdio set
  const char *stdio_string = "stdio";
  // remove one for C terminating NUL character
  const size_t stdio_len = sizeof("stdio") - 1;
  size_t set_number = dandelion_input_set_count();
  for (size_t set_index = 0; set_index < set_number; set_index++) {
    size_t identifier_length = dandelion_input_set_ident_len(set_index);
    const char *set_identifier = dandelion_input_set_ident(set_index);
    if (stdio_len == identifier_length &&
        !strncmp(stdio_string, set_identifier, stdio_len)) {
      setup_stack_data(set_index);
      break;
    }
  }
  // make sure file system is intialized
  int fd;
  mlibc::sys_open("", 0, 0, &fd);
  auto result =
      main_fn(__mlibc_stack_data.argc, __mlibc_stack_data.argv, environ);
  exit(result);
}
