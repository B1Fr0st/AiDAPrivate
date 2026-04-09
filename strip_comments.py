"""
Strip all comments from C/C++ source files and CMake files.
Handles // line comments, /* */ block comments, and # CMake comments.
Preserves string literals containing comment tokens.
"""
import re
import os

WORKSPACES = [
    r"C:\Users\ruar\AiDAPrivate\server",
]

CPP_EXTENSIONS = {'.c', '.cpp', '.h', '.hpp', '.inl', '.js'}
ASM_EXTENSIONS = {'.asm'}
SKIP_DIRS = {'build', '.vs', 'x64', 'Debug', 'Release', 'packages'}


def strip_cpp_comments(source: str) -> str:
    """Remove all C/C++ comments while preserving string/char literals."""
    result = []
    i = 0
    n = len(source)
    while i < n:
        # String literal
        if source[i] == '"':
            j = i + 1
            while j < n:
                if source[j] == '\\':
                    j += 2
                    continue
                if source[j] == '"':
                    j += 1
                    break
                j += 1
            result.append(source[i:j])
            i = j
        # Character literal
        elif source[i] == "'":
            j = i + 1
            while j < n:
                if source[j] == '\\':
                    j += 2
                    continue
                if source[j] == "'":
                    j += 1
                    break
                j += 1
            result.append(source[i:j])
            i = j
        # Block comment
        elif source[i:i+2] == '/*':
            end = source.find('*/', i + 2)
            if end == -1:
                # Unterminated block comment - remove rest
                i = n
            else:
                # Preserve newlines within block comments to keep line numbers
                block = source[i:end+2]
                newlines = block.count('\n')
                result.append('\n' * newlines)
                i = end + 2
        # Line comment
        elif source[i:i+2] == '//':
            # Skip to end of line (but keep the newline)
            j = i + 2
            while j < n and source[j] != '\n':
                j += 1
            i = j
        else:
            result.append(source[i])
            i += 1
    return ''.join(result)


def strip_cmake_comments(source: str) -> str:
    """Remove # comments from CMake files, preserving strings."""
    lines = source.split('\n')
    result = []
    for line in lines:
        in_string = False
        new_line = []
        i = 0
        while i < len(line):
            ch = line[i]
            if ch == '"':
                in_string = not in_string
                new_line.append(ch)
            elif ch == '#' and not in_string:
                # Rest of line is comment - stop here
                break
            else:
                new_line.append(ch)
            i += 1
        result.append(''.join(new_line).rstrip())
    return '\n'.join(result)


def clean_blank_lines(text: str) -> str:
    """
    Remove excessive blank lines. Collapse 3+ consecutive blank lines to 2.
    Also remove trailing whitespace on each line.
    """
    lines = text.split('\n')
    cleaned = []
    blank_count = 0
    for line in lines:
        stripped = line.rstrip()
        if stripped == '':
            blank_count += 1
            if blank_count <= 2:
                cleaned.append('')
        else:
            blank_count = 0
            cleaned.append(stripped)
    # Remove trailing blank lines
    while cleaned and cleaned[-1] == '':
        cleaned.pop()
    # Ensure file ends with newline
    result = '\n'.join(cleaned)
    if result and not result.endswith('\n'):
        result += '\n'
    return result


def process_file(filepath: str, is_cmake: bool = False) -> bool:
    """Process a single file. Returns True if file was modified."""
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        original = f.read()

    if is_cmake:
        processed = strip_cmake_comments(original)
    else:
        processed = strip_cpp_comments(original)

    processed = clean_blank_lines(processed)

    if processed != original:
        with open(filepath, 'w', encoding='utf-8', newline='\n') as f:
            f.write(processed)
        return True
    return False


def strip_asm_comments(source: str) -> str:
    result = []
    i = 0
    n = len(source)
    while i < n:
        if source[i] == '"':
            j = i + 1
            while j < n:
                if source[j] == '\\': j += 2; continue
                if source[j] == '"': j += 1; break
                j += 1
            result.append(source[i:j])
            i = j
        elif source[i] == ';':
            j = i + 1
            while j < n and source[j] != '\n':
                j += 1
            i = j
        else:
            result.append(source[i])
            i += 1
    return ''.join(result)


def process_workspace(workspace: str, modified: list) -> int:
    """Walk one workspace directory, strip comments, return number of files scanned."""
    total = 0
    script_abs = os.path.abspath(__file__)

    for root, dirs, files in os.walk(workspace):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            filepath = os.path.join(root, fname)

            # Never modify the script itself.
            if os.path.abspath(filepath) == script_abs:
                continue

            relpath = os.path.relpath(filepath, workspace)
            display = os.path.join(os.path.basename(workspace), relpath)

            if ext in CPP_EXTENSIONS:
                total += 1
                if process_file(filepath, is_cmake=False):
                    print(f"  MODIFIED: {display}")
                    modified.append(display)
                else:
                    print(f"  unchanged: {display}")
            elif ext in ASM_EXTENSIONS:
                total += 1
                with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                    original = f.read()
                processed = strip_asm_comments(original)
                processed = clean_blank_lines(processed)
                if processed != original:
                    with open(filepath, 'w', encoding='utf-8', newline='\n') as f:
                        f.write(processed)
                    print(f"  MODIFIED: {display}")
                    modified.append(display)
                else:
                    print(f"  unchanged: {display}")

    return total


def main():
    modified = []
    total = 0

    for workspace in WORKSPACES:
        if not os.path.isdir(workspace):
            print(f"[SKIP] Directory not found: {workspace}")
            continue
        print(f"\n[Processing] {workspace}")
        total += process_workspace(workspace, modified)

    print(f"\n=== Done. Scanned {total} file(s), modified {len(modified)} ===")
    for f in modified:
        print(f"  - {f}")


if __name__ == '__main__':
    main()
