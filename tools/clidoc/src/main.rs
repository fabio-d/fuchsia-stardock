// Copyright 2021 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Clidoc generates documentation for host tool commands consisting of their --help output.
use {
    anyhow::{bail, Context, Result},
    argh::FromArgs,
    flate2::{write::GzEncoder, Compression},
    log::{debug, info, LevelFilter},
    std::{
        collections::HashSet,
        env,
        ffi::{OsStr, OsString},
        fs::{self, File},
        io::{BufWriter, Write},
        path::{Path, PathBuf},
        process::Command,
        sync::Once,
    },
    tar::Builder,
};

use simplelog::{Config, SimpleLogger};

/// CliDoc generates documentation for core Fuchsia developer tools.
#[derive(Debug, FromArgs)]
struct Opt {
    // Default input dir is parent dir of this tool, containing host tools exes
    // $FUCHSIA_DIR/out/default/host_x64 or $FUCHSIA_DIR/out/default/host-tools
    /// set the input folder
    #[argh(
        option,
        short = 'i',
        default = "env::current_exe().unwrap().parent().unwrap().to_path_buf()"
    )]
    in_dir: PathBuf,

    /// set the output directory
    #[argh(option, short = 'o', default = "PathBuf::from(\".\".to_string())")]
    out_dir: PathBuf,

    /// reduce text output
    #[argh(switch)]
    quiet: bool,

    /// increase text output
    #[argh(switch, short = 'v')]
    verbose: bool,

    /// path for tarball- if set the output will be compressed as a tarball
    /// and intermediate files will be cleaned up
    /// For example: "clidoc_out.tar.gz". Note that .tar.gz is not automatically
    /// added as a file extension.
    #[argh(option)]
    tarball_dir: Option<PathBuf>,

    /// commands to run, otherwise defaults to internal list of commands.
    /// relative paths are on the input_path. Absolute paths are used as-is.
    #[argh(positional)]
    cmd_list: Vec<PathBuf>,
}

// Formatting styles for codeblocks.
const CODEBLOCK_START: &str = "```none {: style=\"white-space: break-spaces;\" \
        .devsite-disable-click-to-copy}\n";
const CODEBLOCK_END: &str = "```\n";

const HEADER: &str = r#"<!--  DO NOT EDIT THIS FILE DIRECTLY

 This file is generated using clidoc by parsing the help output of this tool.
 Please edit the help output or clidoc's processing of that output to make changes
 to this file.

 -->
 "#;

// TODO(fxb/69336): Move allow list to its own separate config file.
const ALLOW_LIST: &'static [&'static str] = &[
    "blobfs-compression",
    "bootserver",
    "cmc",
    "fconfig",
    "ffx",
    "fidl-format",
    "fidlc",
    "fidlcat",
    "fidlgen",
    "fpublish",
    "fremote",
    "fserve",
    "fssh",
    "fvdl",
    "minfs",
    "pm",
    "symbol-index",
    "symbolize",
    "symbolizer",
    "triage",
    "zbi",
    "zxdb",
];

fn main() -> Result<()> {
    let opt: Opt = argh::from_env();
    run(opt)
}

static INIT_LOGGER: Once = Once::new();

fn set_up_logger(opt: &Opt) {
    INIT_LOGGER.call_once(|| {
        if opt.verbose {
            SimpleLogger::init(LevelFilter::Debug, Config::default())
                .expect("Set logger to debug level");
            debug!("Debug logging enabled.");
        } else if opt.quiet {
            SimpleLogger::init(LevelFilter::Warn, Config::default())
                .expect("Set logger to warn level");
        } else {
            SimpleLogger::init(LevelFilter::Info, Config::default())
                .expect("Set logger to info level");
        }
    });
}

fn run(opt: Opt) -> Result<()> {
    if opt.quiet && opt.verbose {
        bail!("cannot use --quiet and --verbose together");
    }

    set_up_logger(&opt);

    // Set the directory for the command executables.
    let input_path = &opt.in_dir;
    info!("Input dir: {}", input_path.display());

    // Set the directory to output documentation to.
    let output_path = &opt.out_dir;
    info!("Output dir: {}", output_path.display());

    let mut cmd_paths: Vec<PathBuf>;

    if opt.cmd_list.is_empty() {
        debug!("Building cmd list from defaults");
        // Create a set of SDK tools to generate documentation for.
        let allow_list: HashSet<OsString> =
            ALLOW_LIST.iter().cloned().map(OsString::from).collect();
        // Create a vector of full paths to each command in the allow_list.
        cmd_paths = get_command_paths(&input_path, &allow_list)?;
    } else {
        // Use the commands passed on the command line. If they are relative paths,
        // make them absolute based on the input_path.
        cmd_paths = Vec::new();
        for p in opt.cmd_list {
            if p.is_absolute() {
                cmd_paths.push(p);
            } else {
                cmd_paths.push(input_path.join(p));
            }
        }
        debug!("Using cmds from opt.cmd_list: {:?}", cmd_paths);
    }

    // Create the directory for doc files if it doesn't exist.
    create_output_dir(&output_path)
        .context(format!("Unable to create output directory {:?}", output_path))?;

    // Write documentation output for each command.
    for cmd_path in cmd_paths.iter() {
        write_formatted_output(&cmd_path, output_path).context(format!(
            "Unable to write generate doc for {:?} to {:?}",
            cmd_path, output_path
        ))?;
    }

    info!("Generated documentation at dir: {}", &output_path.display());

    if let Some(tardir) = opt.tarball_dir {
        info!("Tarballing output at {:?}", tardir);
        let tar_gz = File::create(tardir)?;
        let enc = GzEncoder::new(tar_gz, Compression::default());
        let mut tar = Builder::new(enc);
        tar.append_dir_all("clidoc/", output_path.to_str().expect("Get file name of outdir"))?;

        info!("Cleaning up {:?}", output_path);
        fs::remove_dir_all(output_path)?
    }
    Ok(())
}

/// Helper function for write_formatted_output.
///
/// Recursively calls `cmd_name`'s subcommands and writes to `output_writer`.
fn recurse_cmd_output<W: Write>(
    cmd_name: &str,
    cmd_path: &PathBuf,
    output_writer: &mut W,
    cmds_sequence: &Vec<&String>,
) -> Result<()> {
    // Create vector to collect subcommands.
    let mut cmds_list: Vec<String> = Vec::new();

    let mut inside_command_section = false;

    // Track command level starting from 0, to set command headers' formatting.
    let cmd_level = cmds_sequence.len();

    // Write out the header.
    let cmd_heading_formatting = "#".repeat(cmd_level + 1);

    // Get terminal output for cmd <subcommands> --help for a given command.
    let lines: Vec<String> = help_output_for(&cmd_path, &cmds_sequence)?;

    // TODO(fxb/85803): This is a short term solution to prevent errantly documentating
    // run-on sentences as args with ffx. Long term solution involves using help-json.
    if lines.len() > 0 {
        let first_line = &lines[0];
        if first_line.contains("Unrecognized argument:") && cmd_path.ends_with("ffx") {
            return Ok(());
        }
    }

    debug!("Processing {:?} {:?}", cmd_path, cmds_sequence);

    writeln!(output_writer, "{} {}\n", cmd_heading_formatting, cmd_name)?;
    writeln!(output_writer, "{}", CODEBLOCK_START)?;

    for line in lines {
        // TODO(fxb/69457): Capture all section headers in addition to "Commands" and "Options".
        match line.to_lowercase().as_str() {
            "subcommands:" | "commands:" => {
                write_heading(output_writer, &line)?;
                inside_command_section = true;
            }
            "options:" => {
                write_heading(output_writer, &line)?;
                inside_command_section = false;
            }
            // Command section ends at a blank line (or end of file).
            "" => {
                writeln!(output_writer, "")?;
                inside_command_section = false;
            }
            // Collect sub-commands into a vector.
            _ if inside_command_section => {
                // Command name is the first word on the line.
                if let Some(command) = line.split_whitespace().next() {
                    match command.as_ref() {
                        "commands" | "subcommands" => {
                            debug!("skipping {:?} to avoid recursion", command);
                        }
                        _ => {
                            cmds_list.push(command.to_string());
                        }
                    }
                    writeln!(output_writer, "{}", line)?;
                }
            }
            _ => {
                if line.contains(&cmd_path.as_path().display().to_string()) {
                    let line_no_path =
                        line.replace(&cmd_path.as_path().display().to_string(), &cmd_name);
                    // Write line after stripping full path preceeding command name.
                    writeln!(output_writer, "{}", line_no_path)?;
                } else if !line.contains("sdk WARN:") && !line.contains("See 'ffx help <command>'")
                {
                    // TODO(fxb/71456): Remove filtering ffx repeated line after documentation standardized.
                    // Write non-header lines unedited.
                    writeln!(output_writer, "{}", line)?;
                }
            }
        }
    }
    // Close preformatting at the end.
    writeln!(output_writer, "{}", CODEBLOCK_END)?;
    cmds_list.sort();

    for cmd in cmds_list {
        // Copy current command sequence and append newest command.
        let mut cmds_sequence = cmds_sequence.clone();
        cmds_sequence.push(&cmd);
        recurse_cmd_output(&cmd, &cmd_path, output_writer, &cmds_sequence)?;
    }

    Ok(())
}

fn write_heading<W: Write>(output_writer: &mut W, heading: &String) -> Result<()> {
    // End preformatting before writing a section header.
    writeln!(output_writer, "{}", CODEBLOCK_END)?;
    // Write the section heading.
    writeln!(output_writer, "__{}__\n", heading)?;
    // Begin preformatting for next section of non-headers.
    writeln!(output_writer, "{}", CODEBLOCK_START)?;
    Ok(())
}

/// Write output of cmd at `cmd_path` to new cmd.md file at `output_path`.
fn write_formatted_output(cmd_path: &PathBuf, output_path: &PathBuf) -> Result<()> {
    // Get name of command from full path to the command executable.
    let cmd_name = cmd_path.file_name().expect("Could not get file name for command");
    let output_md_path = md_path(&cmd_name, &output_path);

    debug!("Generating docs for {:?} to {:?}", cmd_path, output_md_path);

    // Create vector for commands to call in sequence.
    let cmd_sequence = Vec::new();

    // Create a buffer writer to format and write consecutive lines to a file.
    let file = File::create(&output_md_path).context(format!("create {:?}", output_md_path))?;
    let output_writer = &mut BufWriter::new(file);

    let cmd_name = cmd_name.to_str().expect("Could not convert cmd_name from OsStr to str");

    writeln!(output_writer, "{}", HEADER)?;

    // Write ouput for cmd and all of its subcommands.
    recurse_cmd_output(&cmd_name, &cmd_path, output_writer, &cmd_sequence)
}

/// Generate a vector of full paths to each command in the allow_list.
fn get_command_paths(input_path: &Path, allow_list: &HashSet<OsString>) -> Result<Vec<PathBuf>> {
    // Build a set of all file names in the input_path dir.
    let mut files = HashSet::new();
    if let Ok(paths) = fs::read_dir(&input_path) {
        for path in paths {
            if let Ok(path) = path {
                files.insert(path.file_name());
            }
        }
    }

    // Get the intersection of all files and commands in the allow_list.
    let commands: HashSet<_> = files.intersection(&allow_list).collect();
    info!("Including tools: {:?}", commands);

    // Build full paths to allowed commands found in the input_path dir.
    let mut cmd_paths = Vec::new();
    for c in commands.iter() {
        let path = Path::new(&input_path).join(c);
        cmd_paths.push(path);
    }
    Ok(cmd_paths)
}

/// Create the output dir if doesn't exist, recursively creating subdirs in path.
fn create_output_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)
            .with_context(|| format!("Unable to create output directory {}", path.display()))?;
        info!("Created directory {}", path.display());
    }
    Ok(())
}

/// Get cmd --help output when given a full path to a cmd.
fn help_output_for(tool: &Path, subcommands: &Vec<&String>) -> Result<Vec<String>> {
    let output = Command::new(&tool)
        .args(&*subcommands)
        .arg("--help")
        .output()
        .context(format!("Command failed for {:?}", &tool.display()))?;

    let stdout = output.stdout;
    let stderr = output.stderr;

    // Convert string outputs to vector of lines.
    let stdout_string = String::from_utf8(stdout).expect("Help string from utf8");
    let mut combined_lines = stdout_string.lines().map(String::from).collect::<Vec<_>>();

    let stderr_string = String::from_utf8(stderr).expect("Help string from utf8");
    let stderr_lines = stderr_string.lines().map(String::from).collect::<Vec<_>>();

    combined_lines.extend(stderr_lines);

    Ok(combined_lines)
}

/// Given a cmd name and a dir, create a full path ending in cmd.md.
fn md_path(file_stem: &OsStr, dir: &PathBuf) -> PathBuf {
    let mut path = Path::new(dir).join(file_stem);
    path.set_extension("md");
    path
}

#[cfg(test)]
mod tests {
    use {super::*, flate2::read::GzDecoder, tar::Archive};

    #[test]
    fn run_test_commands() {
        let tmp_dir = tempfile::Builder::new().prefix("clidoc-test-out").tempdir().unwrap();
        let argv = [
            "-v",
            "-o",
            &tmp_dir.path().to_str().unwrap(),
            "clidoc_test_data/tool_with_subcommands.sh",
        ];
        let cmd = "clidoc-test";
        let opt = Opt::from_args(&[cmd], &argv).unwrap();
        let generated = tmp_dir.path().join("tool_with_subcommands.md");
        let expected = &opt.in_dir.join("clidoc_test_data/tool_with_subcommands.md");

        run(opt).expect("tool_with_subcommands could not be generated");

        let generated_contents = fs::read_to_string(generated).unwrap();
        let expected_contents = fs::read_to_string(expected).unwrap();

        assert_eq!(generated_contents, expected_contents);
    }

    #[test]
    fn run_test_archive_and_cleanup() {
        let tmp_dir = tempfile::Builder::new().prefix("clidoc-tar-test").tempdir().unwrap();
        let argv = [
            "--tarball-dir",
            "clidoc_out.tar.gz",
            "-v",
            "-o",
            &tmp_dir.path().to_str().unwrap(),
            "clidoc_test_data/tool_with_subcommands.sh",
        ];
        let cmd = "clidoc-test-archive";
        let opt = Opt::from_args(&[cmd], &argv).unwrap();
        run(opt).expect("tool_with_subcommands could not be generated");

        // With the tarball-dir flag set, the md file should be zipped
        // and not exist.
        assert!(!tmp_dir.path().join("tool_with_subcommands.md").exists());

        let tar_gz = File::open("clidoc_out.tar.gz").expect("open tarball");
        let tar = GzDecoder::new(tar_gz);
        let mut archive = Archive::new(tar);
        archive.unpack(".").expect("extract tar");

        assert!(Path::new("clidoc/tool_with_subcommands.md").exists());
    }
}
