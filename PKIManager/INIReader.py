

# Read an INI file into easy-to-access name/value pairs.
#
# SPDX-License-Identifier: BSD-3-Clause
# Port of inih's INIReader (C++) to Python with equivalent behavior.
# https://github.com/benhoyt/inih

from __future__ import annotations
from typing import Dict, Optional
import io


class INIReader:

    def __init__(self, filename: Optional[str] = None, buffer: Optional[bytes | str] = None):
        self._values: Dict[str, str] = {}
        self._error: int = 0
        if filename is not None and buffer is not None:
            raise ValueError("Provide either filename or buffer, not both.")
        if filename is not None:
            try:
                with open(filename, "r", encoding="utf-8") as f:
                    content = f.read()
            except OSError:
                self._error = -1
            else:
                self._error = self._parse_string(content)
        elif buffer is not None:
            if isinstance(buffer, bytes):
                try:
                    content = buffer.decode("utf-8")
                except UnicodeDecodeError:
                    # Fallback similar to permissive readers
                    content = buffer.decode("latin-1", errors="replace")
            else:
                content = str(buffer)
            self._error = self._parse_string(content)
        else:
            # Empty reader with no data
            self._error = 0

    # --- API compatible methods (names mirror C++ version) ---

    def ParseError(self) -> int:
        return self._error

    def Get(self, section: str, name: str, default_value: str) -> str:
        key = self.MakeKey(section, name)
        return self._values.get(key, default_value)

    def GetString(self, section: str, name: str, default_value: str) -> str:
        s = self.Get(section, name, "")
        return s if s != "" else default_value

    def GetInteger(self, section: str, name: str, default_value: int) -> int:
        v = self.Get(section, name, "")
        try:
            # base=0 -> autodetect like strtol
            n = int(v, 0)
        except Exception:
            return default_value
        return n

    # 64-bit in Python just maps to int
    def GetInteger64(self, section: str, name: str, default_value: int) -> int:
        v = self.Get(section, name, "")
        try:
            n = int(v, 0)
        except Exception:
            return default_value
        return n

    def GetUnsigned(self, section: str, name: str, default_value: int) -> int:
        v = self.Get(section, name, "")
        try:
            n = int(v, 0)
            if n < 0:
                return default_value
        except Exception:
            return default_value
        return n

    def GetUnsigned64(self, section: str, name: str, default_value: int) -> int:
        v = self.Get(section, name, "")
        try:
            n = int(v, 0)
            if n < 0:
                return default_value
        except Exception:
            return default_value
        return n

    def GetReal(self, section: str, name: str, default_value: float) -> float:
        v = self.Get(section, name, "")
        try:
            # float() handles decimal and scientific notation; hex floats are not supported in C++ either here
            n = float(v)
        except Exception:
            return default_value
        return n

    def GetBoolean(self, section: str, name: str, default_value: bool) -> bool:
        v = self.Get(section, name, "")
        val = v.strip().lower()
        if val in ("true", "yes", "on", "1"):
            return True
        if val in ("false", "no", "off", "0"):
            return False
        return default_value

    def HasSection(self, section: str) -> bool:
        prefix = self.MakeKey(section, "")
        # Find any key that starts with prefix
        for k in self._values.keys():
            if k.startswith(prefix):
                return True
        return False

    def HasValue(self, section: str, name: str) -> bool:
        return self.MakeKey(section, name) in self._values

    @staticmethod
    def MakeKey(section: str, name: str) -> str:
        key = f"{section}={name}"
        return key.lower()

    # --- Internal parser that emulates inih behavior closely ---

    def _parse_string(self, s: str) -> int:
        current_section = ""
        line_no = 0
        for raw_line in io.StringIO(s):
            line_no += 1
            line = raw_line.strip()
            # Skip comments and blank lines (';' or '#')
            if not line or line.startswith(";") or line.startswith("#"):
                continue
            # Section header
            if line.startswith("[") and line.endswith("]"):
                current_section = line[1:-1].strip()
                continue
            # Key-value pair: look for '=' or ':' like in inih
            sep_idx = -1
            for ch in ("=", ":"):
                idx = line.find(ch)
                if idx != -1:
                    sep_idx = idx
                    break
            if sep_idx == -1:
                # parse error: ill-formed line
                return line_no
            name = line[:sep_idx].strip()
            value = line[sep_idx + 1 :].strip()
            # Remove inline comments if not quoted (basic handling)
            if value and value[0] not in ('"', "'"):
                # Stop at unescaped comment markers ';' or '#'
                for cmt in (";", "#"):
                    cidx = value.find(cmt)
                    if cidx != -1:
                        value = value[:cidx].rstrip()
                        break
            self._value_handler(current_section, name, value)
        return 0

    def _value_handler(self, section: str, name: str, value: Optional[str]) -> None:
        # Mirrors ValueHandler from C++: append with '\n' on duplicate writes
        key = self.MakeKey(section, name)
        existing = self._values.get(key, "")
        to_add = value if value is not None else ""
        if existing:
            self._values[key] = existing + "\n" + to_add
        else:
            self._values[key] = to_add