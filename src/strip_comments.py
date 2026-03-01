"""
Strip all comments from C/C++ source files and CMake files.
Handles // line comments, /* */ block comments, and # CMake comments.
Preserves string literals containing comment tokens.
"""
import re
import os

WORKSPACE = r"C:\Users\diskt\AiDA\src"

CPP_FILES = [
    "actions.cpp",
    "actions.hpp",
    "agentic.cpp",
    "agentic.hpp",
    "agent_tools.cpp",
    "agent_tools.hpp",
    "aida.cpp",
    "aida.hpp",
    "aida_pro.hpp",
    "ai_client.cpp",
    "ai_client.hpp",
    "anti_re.hpp",
    "chat_widget.cpp",
    "chat_widget.hpp",
    "chat_widget_ui.cpp",
    "chat_widget_ui.hpp",
    "ida_utils.cpp",
    "ida_utils.hpp",
    "license.cpp",
    "license.hpp",
    "mcp_server.cpp",
    "mcp_server.hpp",
    "obfuscation.hpp",
    "prompts.hpp",
    "settings.cpp",
    "settings.hpp",
    "ui.cpp",
    "ui.hpp",
    "vmp.hpp",
]

CMAKE_FILES = [
    "CMakeLists.txt",
]


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


def main():
    modified = []
    skipped = []

    for relpath in CPP_FILES:
        filepath = os.path.join(WORKSPACE, relpath)
        if not os.path.exists(filepath):
            print(f"  SKIP (not found): {relpath}")
            skipped.append(relpath)
            continue
        if process_file(filepath, is_cmake=False):
            print(f"  MODIFIED: {relpath}")
            modified.append(relpath)
        else:
            print(f"  unchanged: {relpath}")

    for relpath in CMAKE_FILES:
        filepath = os.path.join(WORKSPACE, relpath)
        if not os.path.exists(filepath):
            print(f"  SKIP (not found): {relpath}")
            skipped.append(relpath)
            continue
        if process_file(filepath, is_cmake=True):
            print(f"  MODIFIED: {relpath}")
            modified.append(relpath)
        else:
            print(f"  unchanged: {relpath}")

    print(f"\n=== Done. Modified {len(modified)} file(s), skipped {len(skipped)} ===")
    for f in modified:
        print(f"  - {f}")


if __name__ == '__main__':
    main()
