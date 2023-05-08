? fprintf(void *, ? *, u8 *);                       /* extern */
? fputc(?, void *);                                 /* extern */
s32 getopt(s32, s32, ? *);                          /* extern */
s32 strcmp(u8 *, ? *);                              /* extern */
? func_00439898(u8 *, ? *);                         /* static */
s32 func_004398FC(u8 *);                            /* static */
extern ? __iob;
extern u8 *optarg;
extern s32 opterr;
extern s32 optind;
static s32 error_threshold = 2;
static s32 error_limit = 0x64;
static s32 strict_ansi_error_severity = 2;
static s32 anachronism_error_severity = 3;
static s32 C_dialect = 2;
static s32 allow_anachronisms = 0;
static s32 exceptions_disabled = 1;
static s32 targ_has_signed_chars = 0;
static s32 allow_dollar_in_id_chars = 0;
static s32 instantiation_mode = 0;
static s32 automatic_instantiation_mode = 1;
static s32 implicit_template_inclusion_mode = 1;
static s32 full_warnings = 0;
static s32 cvdb_preprocessing_only = 0;
static s32 pcc_preprocessing_mode;
static s32 do_preprocessing_only;
static s32 generate_pp_output;
static s32 keep_comments_in_pp_output;
static s32 gen_line_info_in_pp_output;
static u8 *pp_file_name;
static s32 list_included_files;
static s32 list_makefile_dependencies;
static s32 f_raw_listing;
static s32 f_xref_info;
static s32 suppress_back_end;
static s32 suppress_il_lowering;
static s32 suppress_il_file_write;
static s32 suppress_virtual_function_table_definition;
static ? defs_from_cmd_line;
static ? undefs_from_cmd_line;
static u8 *il_file_name;
static u8 *module_list_for_union_init;
static u8 *primary_source_file_name;
static s32 incl_search_path;
static s32 end_incl_search_path;
static s32 sys_incl_search_path;
static ? error_position;
static ? pos_curr_token;
static s32 strict_ansi_mode;
static s32 cfront_compatibility_mode;
static s32 global_optimization_on;
static ? RO_10006804;                               /* unable to generate initializer; const */

void proc_command_line(s32 arg0, s32 arg1) {
    u8 *sp58;
    s32 sp54;
    s32 sp50;
    s32 temp_v0;
    s32 temp_v0_2;
    s32 temp_v0_3;
    s32 var_at;
    s32 var_v0;
    u8 *temp_a0;
    u8 *temp_s0;
    u8 *temp_t1;
    u8 *temp_t3;
    u8 *var_s3;
    u8 temp_v1;

    pos_curr_token.unk0 = 0;
    pos_curr_token.unk4 = 1;
    error_position.unk4 = 1;
    error_position.unk0 = 0;
    sys_incl_search_path = 0;
    end_incl_search_path = 0;
    incl_search_path = 0;
    sp58 = NULL;
    var_s3 = NULL;
    opterr = 0;
    comphdr_save_compilation_flags(arg0, arg1, &end_incl_search_path, &sys_incl_search_path);
    var_v0 = getopt(arg0, arg1, &RO_10006804);
    if (var_v0 != -1) {
        var_at = var_v0 < 0x25;
        do {
            if (var_at == 0) {
                switch (var_v0) {
                case 0x41:
                case 0x61:
                    if ((var_v0 == 0x41) && (optarg != NULL) && ((temp_v1 = *optarg, (temp_v1 == 0x2D)) || (temp_v1 == 0x2B))) {
                        strict_ansi_mode = 1;
                        if (var_v0 == 0x41) {
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
                    var_s3 = optarg;
                    if (var_s3 != NULL) {
                        if (strcmp(var_s3, "none") == 0) {
                            instantiation_mode = 0;
                        } else if (strcmp(var_s3, "all") == 0) {
                            instantiation_mode = 1;
                        } else if (strcmp(var_s3, "used") == 0) {
                            instantiation_mode = 2;
                        } else if (strcmp(var_s3, "local") == 0) {
                            instantiation_mode = 3;
                        } else {
                            str_command_line_error("invalid instantiation mode: ", var_s3);
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
                    fprintf(&__iob + 0x20, "Edison Design Group C/C++ Front End, version %s\n", "2.19");
                    fprintf(&__iob + 0x20, "Copyright 1988-1993 Edison Design Group Inc.\n");
                    fputc(0xA, &__iob + 0x20);
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
                    temp_s0 = optarg;
                    if (*temp_s0 == 0x2D) {
                        command_line_error("missing include file directory name");
                    }
                    add_to_include_search_path(temp_s0);
                    break;
                case 0x44:
                    func_00439898(optarg, &defs_from_cmd_line);
                    break;
                case 0x55:
                    func_00439898(optarg, &undefs_from_cmd_line);
                    break;
                case 0x65:
                    temp_v0 = func_004398FC(optarg);
                    error_limit = temp_v0;
                    if (temp_v0 == 0) {
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
                    if ((strcmp(optarg, "all") != 0) && (strcmp(optarg, "comment") != 0) && (strcmp(optarg, "comments") != 0) && (strcmp(optarg, "trigraphs") != 0)) {
                        fprintf(&__iob + 0x20, "Command-line warning: invalid option: -W%s\n", optarg);
                    }
                    break;
                case 0x58:
                    temp_a0 = optarg + 1;
                    if (*optarg == 0x58) {
                        optarg = temp_a0;
                        f_xref_info = open_output_file(temp_a0, 0, 0, &sp54, &sp50);
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
                }
            } else if (var_v0 != 0x24) {
            default:
                if (optind >= arg0) {
                    optarg = (arg1 + (arg0 * 4))->unk-4;
                } else {
                    optarg = *(arg1 + (optind * 4));
                }
block_86:
                str_command_line_error("invalid option: ", optarg);
            } else {
                allow_dollar_in_id_chars = 1;
            }
            var_v0 = getopt(arg0, arg1, &RO_10006804);
            var_at = var_v0 < 0x25;
        } while (var_v0 != -1);
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
    temp_v0_2 = C_dialect;
    if (strict_ansi_mode != 0) {
        if (temp_v0_2 == 1) {
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
    pcc_preprocessing_mode = temp_v0_2 == 1;
    if (cfront_compatibility_mode != 0) {
        if (exceptions_disabled == 0) {
            command_line_error("support for exceptions cannot be enabled (-x) in cfront mode");
        }
        exceptions_disabled = 1;
    }
    add_default_include_search_path();
    temp_v0_3 = optind;
    sys_incl_search_path = incl_search_path;
    if (temp_v0_3 >= arg0) {
        command_line_error("missing source file name");
        exit_compilation(5);
    }
    optarg = *(arg1 + (temp_v0_3 * 4));
    optind = temp_v0_3 + 1;
    if (strcmp(optarg, "-") == 0) {
        optarg = "-";
    }
    primary_source_file_name = optarg;
    add_to_front_of_include_search_path(gs_directory_of(optarg));
    if (optind < arg0) {
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
