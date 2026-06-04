import os, sys, shutil, subprocess, platform, zipfile, tarfile, stat
from pathlib import Path

def get_script_path():
    return Path(__file__).resolve()

def copy_project(src, dst, script_path, output_name):
    dst.mkdir(parents=True, exist_ok=True)
    for item in src.iterdir():
        if item.samefile(script_path) or item.name == output_name:
            continue
        dest = dst / item.name
        if item.is_dir():
            shutil.copytree(item, dest, dirs_exist_ok=True)
        else:
            shutil.copy2(item, dest)

def create_run_script(output_dir, target_format=None):
    cmd = "vulpin app.vul"
    if target_format:
        cmd += f" --target {target_format}"
    script_path = output_dir / "run.py"
    script_path.write_text(f'''#!/usr/bin/env python3
import subprocess, sys
def main():
    r = subprocess.run("{cmd}", shell=True, cwd=r"{output_dir.resolve()}")
    sys.exit(r.returncode)
if __name__ == "__main__":
    main()
''', encoding="utf-8")
    script_path.chmod(script_path.stat().st_mode | stat.S_IEXEC)
    return script_path

def ensure_pyinstaller():
    try:
        import PyInstaller
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

def build_pyinstaller(run_py, output_dir, name="run"):
    ensure_pyinstaller()
    work = output_dir / "_tmp"
    work.mkdir(exist_ok=True)
    subprocess.check_call([
        sys.executable, "-m", "PyInstaller",
        "--onefile", "--distpath", str(output_dir), "--workpath", str(work),
        "--specpath", str(work), "--name", name, str(run_py)
    ])
    shutil.rmtree(work, ignore_errors=True)
    run_py.unlink()
    return output_dir / (name + (".exe" if platform.system() == "Windows" else ""))

def build_linux_docker(run_py, output_dir, name="run"):
    subprocess.check_call([
        "docker", "run", "--rm",
        "-v", f"{output_dir.resolve()}:/output",
        "-v", f"{run_py.resolve()}:/src/run.py:ro",
        "cdrx/pyinstaller-linux:python3",
        "pyinstaller", "--onefile", "--distpath", "/output",
        "--workpath", "/output/_tmp", "--specpath", "/output/_tmp",
        "--name", name, "/src/run.py"
    ])
    shutil.rmtree(output_dir / "_tmp", ignore_errors=True)
    run_py.unlink()
    return output_dir / name

def build_windows_docker(run_py, output_dir, name="run"):
    subprocess.check_call([
        "docker", "run", "--rm",
        "-v", f"{output_dir.resolve()}:/output",
        "-v", f"{run_py.resolve()}:/src/run.py:ro",
        "cdrx/pyinstaller-windows:python3",
        "wine", "pyinstaller", "--onefile", "--distpath", "Z:\\output",
        "--workpath", "Z:\\output\\_tmp", "--specpath", "Z:\\output\\_tmp",
        "--name", name, "Z:\\src\\run.py"
    ])
    shutil.rmtree(output_dir / "_tmp", ignore_errors=True)
    run_py.unlink()
    return output_dir / (name + ".exe")

def create_zip(source_dir, output_path):
    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for f in source_dir.rglob('*'):
            zf.write(f, f.relative_to(source_dir))
    return output_path

def create_tar_gz(source_dir, output_path):
    with tarfile.open(output_path, "w:gz") as tar:
        tar.add(source_dir, arcname=source_dir.name)
    return output_path

def create_appimage(output_dir, exe_path, name):
    appdir = output_dir / f"{name}.AppDir"
    appdir.mkdir(exist_ok=True)
    shutil.copy(exe_path, appdir / name)
    (appdir / f"{name}.desktop").write_text(f"[Desktop Entry]\nName={name}\nExec={name}\nType=Application\n")
    try:
        subprocess.check_call(["appimagetool", str(appdir), str(output_dir / f"{name}.AppImage")])
    except FileNotFoundError:
        print("appimagetool not found")
        return None
    shutil.rmtree(appdir)
    return output_dir / f"{name}.AppImage"

def main():
    import argparse
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("-o", "--output", dest="output", default="vulpin_build")
    p.add_argument("--target", default=None)
    p.add_argument("--exe-name", default="run")
    p.add_argument("--os", dest="target_os", default="current")
    p.add_argument("--cross", action="store_true")
    p.add_argument("--package", nargs="+", default=[])
    p.add_argument("--keep-py", action="store_true")
    args = p.parse_args()

    cwd = Path.cwd()
    output_dir = cwd / args.output
    script_path = get_script_path()

    # Copy everything from current directory into output_dir,
    # skipping this script and the output folder itself.
    copy_project(cwd, output_dir, script_path, args.output)

    run_py = create_run_script(output_dir, args.target)

    target_os = args.target_os
    if target_os == "all":
        target_list = ["linux", "windows", "macos"]
    else:
        target_list = [target_os]

    for os_name in target_list:
        if os_name == "current":
            os_name = platform.system().lower()
        if os_name == "macos" and platform.system() != "Darwin" and not args.cross:
            continue
        if os_name == "linux" and platform.system() != "Linux":
            if args.cross:
                build_linux_docker(run_py, output_dir, args.exe_name)
            continue
        elif os_name == "windows" and platform.system() != "Windows":
            if args.cross:
                build_windows_docker(run_py, output_dir, args.exe_name)
            continue
        elif os_name in ("linux", "windows", "macos"):
            build_pyinstaller(run_py, output_dir, args.exe_name)
        else:
            build_pyinstaller(run_py, output_dir, args.exe_name)

    if not args.keep_py and run_py.exists():
        run_py.unlink()

    for pkg in args.package:
        if pkg == "zip":
            create_zip(output_dir, output_dir.parent / f"{args.output}.zip")
        elif pkg == "tar.gz":
            create_tar_gz(output_dir, output_dir.parent / f"{args.output}.tar.gz")
        elif pkg == "appimage":
            exe_path = next(output_dir.glob(args.exe_name + "*"), None)
            if exe_path:
                create_appimage(output_dir, exe_path, args.exe_name)
        elif pkg == "dmg" and platform.system() == "Darwin":
            subprocess.check_call(["hdiutil", "create", "-volname", args.exe_name,
                                   "-srcfolder", str(output_dir),
                                   str(output_dir.parent / f"{args.exe_name}.dmg")])

if __name__ == "__main__":
    main()
