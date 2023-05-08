#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdint.h>
#include <string.h>

typedef int32_t s32;
typedef uint8_t u8;

typedef s32 UNK_TYPE;

s32 error_threshold = 2;
s32 error_limit = 0x64;
s32 strict_ansi_error_severity = 2;
s32 anachronism_error_severity = 3;
s32 C_dialect = 2;
s32 allow_anachronisms = 0;
s32 exceptions_disabled = 1;
s32 targ_has_signed_chars = 0;
s32 allow_dollar_in_id_chars = 0;
s32 instantiation_mode = 0;
s32 automatic_instantiation_mode = 1;
s32 implicit_template_inclusion_mode = 1;
s32 full_warnings = 0;
s32 cvdb_preprocessing_only = 0;
s32 pcc_preprocessing_mode;
s32 do_preprocessing_only;
s32 generate_pp_output;
s32 keep_comments_in_pp_output;
s32 gen_line_info_in_pp_output;
u8* pp_file_name;
s32 list_included_files;
s32 list_makefile_dependencies;
s32 f_raw_listing;
s32 f_xref_info;
s32 suppress_back_end;
s32 suppress_il_lowering;
s32 suppress_il_file_write;
s32 suppress_virtual_function_table_definition;
UNK_TYPE defs_from_cmd_line;
UNK_TYPE undefs_from_cmd_line;
u8* il_file_name;
u8* module_list_for_union_init;
u8* primary_source_file_name;
s32 incl_search_path;
s32 end_incl_search_path;
s32 sys_incl_search_path;
s32 strict_ansi_mode;
s32 cfront_compatibility_mode;
s32 global_optimization_on;

// #define DEBUG_STUFF 1

void command_line_error(const char* msg) {
#if DEBUG_STUFF
    fprintf(stderr, "%s: %s\n", __func__, msg);
#endif
    exit(1);
}

void str_command_line_error(const char* msg, const char* other) {
#if DEBUG_STUFF
    fprintf(stderr, "%s: %s %s\n", __func__, msg, other);
#endif
    exit(1);
}

void add_to_include_search_path(const char* arg) {
#if DEBUG_STUFF
    fprintf(stderr, "%s: %s\n", __func__, arg);
#endif
}

void func_00439898(const char* arg, UNK_TYPE* arg1) {
#if DEBUG_STUFF
    fprintf(stderr, "%s: %s\n", __func__, arg);
#endif
}
int func_004398FC(const char* arg) {
#if DEBUG_STUFF
    fprintf(stderr, "%s: %s\n", __func__, arg);
#endif
    return 0;
}

int open_output_file(const char* arg, int arg1, int arg2, int* arg3, int* arg4) {
#if DEBUG_STUFF
    fprintf(stderr, "%s: %s\n", __func__, arg);
#endif
    *arg3 = 0;
    *arg4 = 0;
    return 0;
}
int reopen_error_output_file(const char* arg, int* arg3, int* arg4) {
#if DEBUG_STUFF
    fprintf(stderr, "%s: %s\n", __func__, arg);
#endif
    *arg3 = 0;
    *arg4 = 0;
    return 0;
}

int sgi_ext_proc_option(const char* msg) {
#if DEBUG_STUFF
    fprintf(stderr, "%s: %s\n", __func__, msg);
#endif
    return 0;
}
int sgi_ext_proc_fe_option(const char* msg) {
#if DEBUG_STUFF
    fprintf(stderr, "%s: %s\n", __func__, msg);
#endif
    return 0;
}
int mbe_proc_option(const char* msg) {
#if DEBUG_STUFF
    fprintf(stderr, "%s: %s\n", __func__, msg);
#endif
    return 0;
}

void add_default_include_search_path(void) {
#if DEBUG_STUFF
    fprintf(stderr, "%s\n", __func__);
#endif
}

void exit_compilation(int number) {
#if DEBUG_STUFF
    fprintf(stderr, "%s: %i\n", __func__, number);
#endif
    exit(number);
}

int gs_directory_of(const char* arg) {
#if DEBUG_STUFF
    fprintf(stderr, "%s: %s\n", __func__, arg);
#endif
    return 0;
}

void add_to_front_of_include_search_path(int arg) {
#if DEBUG_STUFF
    fprintf(stderr, "%s: %i\n", __func__, arg);
#endif
}

void proc_command_line(int argc, char** argv) {
    u8* sp58;
    s32 sp54;
    s32 sp50;
    s32 temp_v0;
    s32 temp_v0_2;
    s32 temp_v0_3;
    s32 var_at;
    s32 var_v0;
    u8* temp_a0;
    u8* temp_s0;
    u8* temp_t1;
    u8* temp_t3;
    u8* var_s3;
    u8 temp_v1;

    int c;

    while ((c = getopt(argc, argv, "A:BCEHKMNOPTabnsuvwxrmpzV$I:D:U:e:L:X:S:o:i:d:t:F:Y:Z:W:Q:")) != -1) {
        fprintf(stderr, "optarg: %s\n", optarg);
        fprintf(stderr, "optind: %i\n", optind);
        fprintf(stderr, "c:      %X\n", c);
        fprintf(stderr, "\n");

        switch (c) {
            case 0x24:
                allow_dollar_in_id_chars = 1;
                break;

            case 0x41:
            case 0x61:
                if ((c == 0x41) && (optarg != NULL) && ((*optarg == 0x2D) || (*optarg == 0x2B))) {
                    strict_ansi_mode = 1;
                    if (c == 0x41) {
                        strict_ansi_error_severity = 3;
                    } else {
                        strict_ansi_error_severity = 2;
                    }
                    optind -= 1;
                }
                break;
            case 0x45:
                do_preprocessing_only = 1;
                cvdb_preprocessing_only = 1;
                generate_pp_output = 1;
                gen_line_info_in_pp_output = 1;
                break;
            case 0x50:
                do_preprocessing_only = 1;
                cvdb_preprocessing_only = 1;
                generate_pp_output = 1;
                gen_line_info_in_pp_output = 0;
                break;
            case 0x43:
                keep_comments_in_pp_output = 1;
                break;
            case 0x4B:
                C_dialect = 1;
                break;
            case 0x4D:
                do_preprocessing_only = 1;
                cvdb_preprocessing_only = 1;
                generate_pp_output = 0;
                list_included_files = 0;
                list_makefile_dependencies = 1;
                error_threshold = 3;
                break;
            case 0x48:
                do_preprocessing_only = 1;
                cvdb_preprocessing_only = 1;
                generate_pp_output = 0;
                list_included_files = 1;
                list_makefile_dependencies = 0;
                error_threshold = 3;
                break;
            case 0x4E:
                suppress_il_lowering = 1;
                suppress_back_end = 1;
                break;
            case 0x4F:
                allow_anachronisms = 1;
                break;
            case 0x62:
                cfront_compatibility_mode = 1;
                C_dialect = 2;
                exceptions_disabled = 1;
                break;
            case 0x6E:
                suppress_back_end = 1;
                suppress_il_file_write = 1;
                suppress_il_lowering = 1;
                break;
            case 0x73:
                targ_has_signed_chars = 1;
                break;
            case 0x74:
                if (optarg != NULL) {
                    if (strcmp(optarg, "none") == 0) {
                        instantiation_mode = 0;
                    } else if (strcmp(optarg, "all") == 0) {
                        instantiation_mode = 1;
                    } else if (strcmp(optarg, "used") == 0) {
                        instantiation_mode = 2;
                    } else if (strcmp(optarg, "local") == 0) {
                        instantiation_mode = 3;
                    } else {
                        str_command_line_error("invalid instantiation mode: ", optarg);
                    }
                }
                break;
            case 0x54:
                automatic_instantiation_mode = 0;
                break;
            case 0x42:
                implicit_template_inclusion_mode = 0;
                break;
            case 0x75:
                targ_has_signed_chars = 0;
                break;
            case 0x56:
                suppress_virtual_function_table_definition = 1;
                break;
            case 0x76:

                fprintf(stderr, "Edison Design Group C/C++ Front End, version %s\n", "2.19");

                fprintf(stderr, "Copyright 1988-1993 Edison Design Group Inc.\n");

                fputc(0xA, stderr);
                break;
            case 0x77:
                error_threshold = 3;
                break;
            case 0x72:
                error_threshold = 1;
                full_warnings = 1;
                break;
            case 0x6D:
                C_dialect = 0;
                break;
            case 0x70:
                C_dialect = 2;
                break;
            case 0x78:
                exceptions_disabled = 0;
                break;
            case 0x49:
                if (*optarg == 0x2D) {
                    command_line_error("missing include file directory name");
                }
                add_to_include_search_path(optarg);
                break;
            case 0x44:
                func_00439898(optarg, &defs_from_cmd_line);
                break;
            case 0x55:
                func_00439898(optarg, &undefs_from_cmd_line);
                break;
            case 0x65:
                error_limit = func_004398FC(optarg);
                if (error_limit == 0) {
                    str_command_line_error("invalid error limit: ", optarg);
                }
                break;
            case 0x4C:
                f_raw_listing = open_output_file(optarg, 0, 0, &sp54, &sp50);
                if (sp50 != 0) {
                    str_command_line_error("invalid raw-listing output file ", optarg);
                } else if (sp54 != 0) {
                    str_command_line_error("cannot open raw-listing output file ", optarg);
                }
                break;
            case 0x57:
                if ((strcmp(optarg, "all") != 0) && (strcmp(optarg, "comment") != 0) &&
                    (strcmp(optarg, "comments") != 0) && (strcmp(optarg, "trigraphs") != 0)) {

                    fprintf(stderr, "Command-line warning: invalid option: -W%s\n", optarg);
                }
                break;
            case 0x58:
                if (*optarg == 0x58) {
                    optarg = optarg + 1;
                    f_xref_info = open_output_file(optarg, 0, 0, &sp54, &sp50);
                    if (sp50 != 0) {
                        str_command_line_error("invalid cross-reference output file ", optarg);
                    } else if (sp54 != 0) {
                        str_command_line_error("cannot open cross-reference output file ", optarg);
                    }
                }
                break;
            case 0x53:
                reopen_error_output_file(optarg, &sp54, &sp50);
                if (sp50 != 0) {
                    str_command_line_error("invalid error output file ", optarg);
                } else if (sp54 != 0) {
                    str_command_line_error("cannot open error output file ", optarg);
                }
                break;
            case 0x6F:
                sp58 = optarg;
                break;

            case 0x69:
                module_list_for_union_init = optarg;
                break;
            case 0x64:
                optarg = "-d";
                goto block_86;
            case 0x59:
                if (sgi_ext_proc_option(optarg) != 0) {
                    str_command_line_error("error in sgi extension option argument -Y", optarg);
                }
                break;
            case 0x7A:
                global_optimization_on = 1;
                break;
            case 0x51:
                if (sgi_ext_proc_fe_option(optarg) != 0) {
                    str_command_line_error("error in sgi extension option argument -Q", optarg);
                }
                break;
            case 0x5A:
                if (mbe_proc_option(optarg) != 0) {
                    str_command_line_error("error in mbe option argument -Z", optarg);
                }
                break;

            default:
                if (optind >= argc) {
                    optarg = argv[argc - 1];
                } else {
                    optarg = argv[optind];
                }
            block_86:
                str_command_line_error("invalid option: ", optarg);
                break;
        }
    }

    if (C_dialect != 2) {
        if (allow_anachronisms != 0) {
            command_line_error("anachronism option (-O) can only be used when compiling C++");
        }
        if (suppress_virtual_function_table_definition != 0) {
            command_line_error("virtual function tables can only be suppressed (-V) when compiling C++");
        }
        if (var_s3 != NULL) {
            command_line_error("instantiation mode (-t) can only be used when compiling C++");
        }
        if (automatic_instantiation_mode != 1) {
            command_line_error("automatic instantiation mode (-T) can only be used when compiling C++");
        }
        if (implicit_template_inclusion_mode != 1) {
            command_line_error("implicit template inclusion mode (-B) can only be used when compiling C++");
        }
        if (exceptions_disabled != 1) {
            if (exceptions_disabled != 0) {
                command_line_error("support for exceptions can be disabled (-x) only when compiling C++");
            } else {
                command_line_error("support for exceptions can be enabled (-x) only when compiling C++");
            }
        }
    }

    if (strict_ansi_mode != 0) {
        if (C_dialect == 1) {
            command_line_error("strict ANSI mode is incompatible with K&R mode");
        }
        if (cfront_compatibility_mode != 0) {
            command_line_error("strict ANSI mode is incompatible with cfront mode");
        }
        if (allow_anachronisms != 0) {
            command_line_error("strict ANSI mode is incompatible with allowing anachronisms");
        }
        if (strict_ansi_error_severity < error_threshold) {
            error_threshold = strict_ansi_error_severity;
        }
    }
    if (allow_anachronisms != 0) {
        anachronism_error_severity = 2;
    } else {
        anachronism_error_severity = 3;
    }
    pcc_preprocessing_mode = C_dialect == 1;
    if (cfront_compatibility_mode != 0) {
        if (exceptions_disabled == 0) {
            command_line_error("support for exceptions cannot be enabled (-x) in cfront mode");
        }
        exceptions_disabled = 1;
    }
    add_default_include_search_path();

    sys_incl_search_path = incl_search_path;
    if (optind >= argc) {
        command_line_error("missing source file name");
        exit_compilation(5);
    }
    optarg = argv[optind];
    optind = optind + 1;
    if (strcmp(optarg, "-") == 0) {
        optarg = "-";
    }
    primary_source_file_name = optarg;
    add_to_front_of_include_search_path(gs_directory_of(optarg));
    if (optind < argc) {
        command_line_error("too many arguments on command line");
    }
    if (do_preprocessing_only != 0) {
        temp_t1 = sp58;
        suppress_back_end = 1;
        sp58 = NULL;
        suppress_il_file_write = 1;
        suppress_il_lowering = 1;
        pp_file_name = temp_t1;
    } else {
        temp_t3 = sp58;
        if (suppress_il_file_write == 0) {
            sp58 = NULL;
            il_file_name = temp_t3;
        }
    }
    if (sp58 != NULL) {
        command_line_error("-o was specified, but no output file is needed");
    }
}

int main(int argc, char** argv) {
    int aflag = 0;
    int bflag = 0;
    char* cvalue = NULL;
    int index;

    proc_command_line(argc, argv);

    return 0;
}
