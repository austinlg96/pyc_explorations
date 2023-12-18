import io
import logging
from datetime import datetime
from enum import IntFlag
from importlib import util
from pathlib import Path
from py_compile import PycInvalidationMode
from py_compile import compile as compile_pyc
from typing import Literal, Optional

logger = logging.getLogger(__name__)

class PycBitField(IntFlag):
    # Bits as defined per PEP 552
    hash_based = 1
    check_source = 2

    # Aliases
    timestamp_based = 0
    unchecked_hash = 1
    checked_hash = 3

    # Maximum size of the bitfield.
    MAX = 2^32 - 1

    def is_hash_based(self):
        return bool(PycBitField.hash_based & self)

    def hash_is_checked(self):
        return bool(PycBitField.check_source & self)

    def is_timestamp_based(self, strict: bool = False):
        if strict:
            # PEP 552 technically says that the bitfield has to be entirely empty for it to be timestamp based.
            return self == 0
        else:
            # This is a looser definition that is probably more future-proof.
            return not self.is_hash_based()

class PycFile():
    HEADER_WORD_SIZE = 4
    HEADER_LEN = 16

    def __init__(self, header_bytes: bytes = 16 * b"\x00", bytecode_bytes: bytes = b""):
        self.header_io = io.BytesIO(header_bytes)
        self.bytecode_io = io.BytesIO(bytecode_bytes)
        self.path: Optional[Path] = None

        self.header = self.header_io.getbuffer()[:self.HEADER_LEN]
        self.magic_bytes_view = self.header[0:4]
        self.bit_field_view = self.header[4:8]

    @classmethod
    def from_file(cls, pyc_file: Path):
        obj = cls()
        obj.path = pyc_file
        obj.reload_from_disk()
        return obj

    def reload_from_disk(self):
        if self.path is None:
            raise ValueError('Must set a path before loading from disk.')
        
        with self.path.open('rb') as original_file:
            original_file_bytes = original_file.read()

            header_bytes = original_file_bytes[:16]
            self.header[:16] = header_bytes

            bytecode_bytes = original_file_bytes[16:]
            self.bytecode_io = io.BytesIO(bytecode_bytes)

    @property
    def magic_bytes(self) -> bytes:
        return self.magic_bytes_view.tobytes()

    @property
    def bit_field(self) -> PycBitField:
        return PycBitField(int.from_bytes(self.bit_field_view, byteorder='little'))
    
    @bit_field.setter
    def bit_field(self, val: PycBitField):
        b = val.to_bytes(length=4, byteorder='little', signed=False)
        self.bit_field_view[:] = b

    @property
    def src_hash_view(self) -> memoryview:
        if self.is_hash_based():
            return self.header[8:16]
        else:
            raise ValueError('Operation only available for a hash-based pyc file.')

    @property
    def src_hash(self) -> bytes:
        return self.src_hash_view.tobytes()

    @property
    def src_timestamp_view(self) -> memoryview:
        if self.is_timestamp_based():
            return self.header[8:12]
        else:
            raise ValueError('Operation only available for a timestamp-based pyc file.')
    
    @property
    def src_timestamp_bytes(self) -> bytes:
        return self.src_timestamp_view.tobytes()
    
    @property
    def src_timestamp_int(self) -> int:
        return int.from_bytes(self.src_timestamp_view, signed=True, byteorder='little')
    
    @property
    def src_timestamp(self) -> datetime:
        return datetime.fromtimestamp(self.src_timestamp_int)

    @src_timestamp.setter
    def src_timestamp(self, dt: datetime):
        unix_seconds = int(dt.timestamp())
        ts_bytes = unix_seconds.to_bytes(length = 4,byteorder='little', signed=True)
        self.src_timestamp_view[:] = ts_bytes
    
    @property
    def src_size_view(self) -> memoryview:
        if self.is_timestamp_based():
            return self.header[12:16]
        else:
            raise ValueError('Operation only available for a timestamp-based pyc file.')

    @property
    def src_size(self) -> int:
        return int.from_bytes(self.src_size_view)

    def is_hash_based(self) -> bool:
        return self.bit_field.is_hash_based()

    def hash_is_checked(self) -> bool:
        return self.bit_field.hash_is_checked()
    
    def is_timestamp_based(self, strict:bool = False):
        return self.bit_field.is_timestamp_based(strict=strict)
        
    def write_to_file(self, output_path: Optional[Path] = None):
        output_path = output_path if output_path else self.path
        if output_path is None:
            raise ValueError('A path must pre-exist or one must be supplied.')
        with output_path.open('wb') as f:
            self.header_io.seek(0)
            f.write(self.header_io.read())
            self.bytecode_io.seek(0)
            f.write(self.bytecode_io.read())
        self.path = output_path
        self.reload_from_disk()

    def file_details(self):
        return f'Path: {self.path} | {self.hash_based_details() if self.is_hash_based() else self.timestamp_based_details()}'

    def hash_based_details(self):
        return f'src_hash: {self.src_hash.hex()} | check_source: {self.hash_is_checked()}'
    
    def timestamp_based_details(self):
        return f'ts: {self.src_timestamp} | size: {self.src_size}'

    @classmethod
    def details_from_path(cls, path: Path | str):
        # Given the path to a .py or .pyc file, returns details about it.
        path = Path(path)

        if path.suffix == ".py":
            path = Path(util.cache_from_source(str(path)))
        
        try:
            pyc_obj = PycFile.from_file(path)
            return pyc_obj.file_details()
        except FileNotFoundError:
            return f"Path: {path} | DNE"

    
def pyc_path(py_file: Path) -> Path:
    return Path(util.cache_from_source(str(py_file)))

def main(source: str | Path, target: str | Path, target_type: Literal['py'] | Literal['pyc'] = 'py', dfile: Optional[str | Path] = None, invalidation_mode: PycInvalidationMode = PycInvalidationMode.UNCHECKED_HASH):
    source = Path(source)
    target = Path(target)

    match target_type:
        case 'py':
            target_pyc = pyc_path(target)
            dfile = Path(dfile) if dfile else target

        case 'pyc':
            target_pyc = target
            if dfile:
                dfile = Path(dfile)
            else:
                # TODO: Handle this better?
                Path('definitely_not_poison.py') 
                logger.warning('Used generic dfile name.')

    match invalidation_mode:
        case PycInvalidationMode.UNCHECKED_HASH:
            logger.info(f"Compileing pyc from {SOURCE} to {target_pyc} via UNCHECKED_HASH mode.")
            compile_pyc(str(SOURCE), cfile=str(target_pyc), dfile="", invalidation_mode=PycInvalidationMode.UNCHECKED_HASH)
        case _:
            raise NotImplementedError('This invalidation mode has not yet been implemented.')

if __name__ == '__main__':

    SOURCE = Path('./poison.py')

    TARGET = Path('./module') / "__init__.py"

    main(source = SOURCE, target = TARGET)
