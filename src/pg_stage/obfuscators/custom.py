import datetime
import io
import struct
import sys
import zlib
from abc import ABCMeta, abstractmethod
from contextlib import suppress
from dataclasses import dataclass, field
from enum import Enum
from typing import BinaryIO, Iterator, Optional, Union

from pg_stage.obfuscators.plain import PlainObfuscator

Version = tuple[int, int, int]
DumpId = int
Offset = int


class PostgreSQLVersions:
    """Константы версий PostgreSQL для совместимости формата дампов."""

    V1_12 = (1, 12, 0)
    V1_13 = (1, 13, 0)
    V1_14 = (1, 14, 0)
    V1_15 = (1, 15, 0)
    V1_16 = (1, 16, 0)


class OffsetPosition:
    """Константы позиции смещения."""

    SET = 2
    NOT_SET = 1


class BlockType:
    """Идентификаторы типов блоков."""

    DATA = b'\x01'
    BLOBS = b'\x02'
    END = b'\x04'


class Constants:
    """Общие константы."""

    MAGIC_HEADER = b'PGDMP'
    CUSTOM_FORMAT = 1
    DEFAULT_BUFFER_SIZE = 2 * 1024 * 1024  # 2MB для чтения блоков
    MAX_CHUNK_SIZE = 50 * 1024 * 1024
    COMPRESSION_LEVEL = 6
    OUTPUT_CHUNK_SIZE = 512 * 1024  # 512KB - размер выходных сжатых чанков


class PgDumpError(Exception):
    """Базовое исключение для ошибок обработки дампов PostgreSQL."""


class CompressionMethod(Enum):
    """Поддерживаемые методы сжатия."""

    NONE = 'none'
    RAW = 'raw'
    ZLIB = 'zlib'
    LZ4 = 'lz4'

    def __str__(self) -> str:
        return self.value


class SectionType(Enum):
    """Типы секций дампа."""

    PRE_DATA = 'SECTION_PRE_DATA'
    DATA = 'SECTION_DATA'
    POST_DATA = 'SECTION_POST_DATA'
    NONE = 'SECTION_NONE'


@dataclass(frozen=True)
class Header:
    """Информация заголовка файла дампа PostgreSQL."""

    magic: bytes
    version: Version
    database_name: str
    server_version: str
    pgdump_version: str
    compression_method: CompressionMethod
    create_date: datetime.datetime
    int_size: int = 4
    offset_size: int = 8


@dataclass(frozen=True)
class TocEntry:
    """Запись оглавления (Table of Contents)."""

    dump_id: DumpId
    section: SectionType
    had_dumper: bool
    tag: Optional[str] = None
    tablespace: Optional[str] = None
    namespace: Optional[str] = None
    tableam: Optional[str] = None
    owner: Optional[str] = None
    desc: Optional[str] = None
    defn: Optional[str] = None
    drop_stmt: Optional[str] = None
    copy_stmt: Optional[str] = None
    with_oids: Optional[str] = None
    oid: Optional[str] = None
    table_oid: Optional[str] = None
    data_state: int = 0
    offset: Offset = 0
    dependencies: list[DumpId] = field(default_factory=list)


@dataclass(frozen=True)
class Dump:
    """Полная структура файла дампа."""

    header: Header
    toc_entries: list[TocEntry]

    def get_table_data_entries(self) -> Iterator[TocEntry]:
        """
        Получить все записи данных таблиц.
        :return: итератор записей с данными таблиц
        """
        return (entry for entry in self.toc_entries if entry.desc == 'TABLE DATA')

    def get_comment_entries(self) -> Iterator[TocEntry]:
        """
        Получить все записи комментариев.
        :return: итератор записей комментариев
        """
        return (entry for entry in self.toc_entries if entry.desc == 'COMMENT')

    def get_entry_by_id(self, dump_id: DumpId) -> Optional[TocEntry]:
        """
        Найти запись TOC по ID дампа.
        :param dump_id: идентификатор записи в дампе
        :return: запись TOC или None
        """
        return next((entry for entry in self.toc_entries if entry.dump_id == dump_id), None)


class DataParser(metaclass=ABCMeta):
    """Протокол для реализации обработчиков данных."""

    @abstractmethod
    def parse(self, data: Union[str, bytes]) -> Union[str, bytes]:
        """
        Обработать данные и вернуть модифицированную версию.
        :param data: исходные данные (строка или байты)
        :return: обработанные данные
        """
        raise NotImplementedError()


class PgStageParser(DataParser):
    """Процессор обфускации с потоковой построчной обработкой."""

    def __init__(self, parser):
        """
        :param parser: функция парсинга из обфускатора (PlainObfuscator._parse_line)
        """
        self.parser = parser

    def parse(self, data: Union[str, bytes]) -> Union[str, bytes]:
        """
        Применить обфускацию к данным.
        :param data: исходные данные (строка или байты)
        :return: обработанные данные
        """
        if not data:
            return data
        if isinstance(data, str):
            return self.parser(line=data)
        return data

    def process_line(self, line: str) -> str:
        """
        Обработать одну строку через парсер.
        :param line: строка данных (без \\n)
        :return: обработанная строка
        """
        return self.parser(line=line)


class BufferedStreamReader:
    """
    Читает данные из входного потока блоками, позволяет копировать прочитанное
    в output_stream (bypass). Использует кольцевой буфер для O(1) чтения.
    """

    def __init__(self, input_stream: BinaryIO, output_stream: BinaryIO):
        """
        :param input_stream: Входной поток (например, stdout процесса)
        :param output_stream: Исходящий поток для копии (например, sys.stdout)
        """
        self._in_stream = input_stream
        self._out_stream = output_stream
        self._chunks: list[bytes] = []
        self._chunks_total = 0
        self._chunk_offset = 0
        self._bypass = False

    def bypass_on(self) -> None:
        """Включить дублирование данных в output_stream."""
        self._bypass = True

    def bypass_off(self) -> None:
        """Выключить дублирование данных."""
        self._bypass = False

    def read(self, size: int) -> bytes:
        """
        Чтение ровно size байт из потока. O(1) амортизированная сложность.
        :param size: количество байт для чтения
        :return: прочитанные байты
        """
        if size <= 0:
            return b''

        while self._chunks_total - self._chunk_offset < size:
            chunk = self._in_stream.read(Constants.DEFAULT_BUFFER_SIZE)
            if not chunk:
                break
            self._chunks.append(chunk)
            self._chunks_total += len(chunk)

        available = min(size, self._chunks_total - self._chunk_offset)
        if available == 0:
            return b''

        if len(self._chunks) == 1 and self._chunk_offset == 0 and available == len(self._chunks[0]):
            data = self._chunks[0]
            self._chunks.clear()
            self._chunks_total = 0
            self._chunk_offset = 0
        else:
            data = self._collect(available)

        if self._bypass:
            self._out_stream.write(data)

        return data

    def _collect(self, size: int) -> bytes:
        """Собрать size байт из чанков."""
        parts = []
        remaining = size
        while remaining > 0 and self._chunks:
            chunk = self._chunks[0]
            chunk_avail = len(chunk) - self._chunk_offset
            if chunk_avail <= remaining:
                parts.append(chunk[self._chunk_offset:] if self._chunk_offset else chunk)
                remaining -= chunk_avail
                self._chunks.pop(0)
                self._chunks_total -= len(chunk)
                self._chunk_offset = 0
            else:
                parts.append(chunk[self._chunk_offset:self._chunk_offset + remaining])
                self._chunk_offset += remaining
                remaining = 0
        return b''.join(parts)


class DumpIO:
    """Утилиты бинарного I/O для формата дампов PostgreSQL."""

    def __init__(self, int_size: int = 4, offset_size: int = 8):
        """
        Инициализация с размерами типов данных.
        :param int_size: размер целого числа в байтах
        :param offset_size: размер смещения в байтах
        """
        self.int_size = int_size
        self.offset_size = offset_size
        # Предкомпилируем для скорости
        self._byte_struct = struct.Struct('B')
        self._int_unpack = struct.Struct(f'B{int_size}B').unpack
        self._offset_unpack = struct.Struct(f'{offset_size}B').unpack

    def read_byte(self, stream: Union[BinaryIO, BufferedStreamReader]) -> int:
        """
        Чтение одного байта.
        :param stream: поток для чтения
        :return: значение байта
        """
        data = stream.read(1)
        if not data:
            message = 'Unexpected EOF while reading byte'
            raise PgDumpError(message)
        return struct.unpack('B', data)[0]

    def read_int(self, stream: Union[BinaryIO, BufferedStreamReader]) -> int:
        """
        Чтение знакового целого числа с переменным размером.
        :param stream: поток для чтения
        :return: значение целого числа
        """
        data = stream.read(self.int_size + 1)
        if len(data) != self.int_size + 1:
            message = 'Unexpected EOF while reading int'
            raise PgDumpError(message)

        unpacked = self._int_unpack(data)
        sign = unpacked[0]
        value = sum(b << (i * 8) for i, b in enumerate(unpacked[1:]) if b != 0)
        return -value if sign else value

    def read_string(self, stream: Union[BinaryIO, BufferedStreamReader]) -> str:
        """
        Чтение строки UTF-8 с префиксом длины.
        :param stream: поток для чтения
        :return: строка
        """
        length = self.read_int(stream)
        if length <= 0:
            return ''

        data = stream.read(length)
        if len(data) != length:
            message = f'Expected {length} bytes, got {len(data)}'
            raise PgDumpError(message)

        try:
            return data.decode('utf-8')
        except UnicodeDecodeError as error:
            message = f'Invalid UTF-8 string: {error}'
            raise PgDumpError(message) from error

    def read_offset(self, stream: Union[BinaryIO, BufferedStreamReader]) -> Offset:
        """
        Чтение значения смещения.
        :param stream: поток для чтения
        :return: значение смещения
        """
        offset = 0
        for i in range(self.offset_size):
            byte_value = self.read_byte(stream)
            offset |= byte_value << (i * 8)
        return offset

    def write_int(self, value: int) -> bytes:
        """
        Запись знакового целого числа.
        :param value: значение для записи
        :return: байты для записи
        """
        is_negative = value < 0
        value = abs(value)

        result = bytearray()
        result.append(1 if is_negative else 0)

        for i in range(self.int_size):
            result.append((value >> (i * 8)) & 0xFF)

        return bytes(result)


class HeaderParser:
    """Парсер заголовков файлов дампов PostgreSQL."""

    def __init__(self, dio: DumpIO):
        """
        Инициализация парсера.
        :param dio: объект для работы с бинарным I/O
        """
        self.dio = dio

    def parse(self, stream: Union[BinaryIO, BufferedStreamReader]) -> Header:
        """
        Парсинг заголовка файла дампа.
        :param stream: поток для чтения
        :return: объект заголовка
        """
        magic = stream.read(5)
        if magic != Constants.MAGIC_HEADER:
            message = f'Invalid magic header: {magic!r}'
            raise PgDumpError(message)

        version = (self.dio.read_byte(stream), self.dio.read_byte(stream), self.dio.read_byte(stream))

        self._validate_version(version)

        int_size = self.dio.read_byte(stream)
        offset_size = self.dio.read_byte(stream)
        self.dio.int_size = int_size
        self.dio.offset_size = offset_size

        format_byte = self.dio.read_byte(stream)
        if format_byte != Constants.CUSTOM_FORMAT:
            message = f'Unsupported format: {format_byte}'
            raise PgDumpError(message)

        compression_method = self._parse_compression(stream, version)
        create_date = self._parse_date(stream)

        database_name = self.dio.read_string(stream)
        server_version = self.dio.read_string(stream)
        pgdump_version = self.dio.read_string(stream)

        return Header(
            magic=magic,
            version=version,
            database_name=database_name,
            server_version=server_version,
            pgdump_version=pgdump_version,
            compression_method=compression_method,
            create_date=create_date,
            int_size=int_size,
            offset_size=offset_size,
        )

    def _validate_version(self, version: Version) -> None:
        """
        Валидация версии формата дампа.
        :param version: версия для проверки
        """
        if version < PostgreSQLVersions.V1_12 or version > PostgreSQLVersions.V1_16:
            version_str = '.'.join(map(str, version))
            message = f'Unsupported version: {version_str}'
            raise PgDumpError(message)

    def _parse_compression(self, stream: Union[BinaryIO, BufferedStreamReader], version: Version) -> CompressionMethod:
        """
        Парсинг метода сжатия в зависимости от версии.
        :param stream: поток для чтения
        :param version: версия формата
        :return: метод сжатия
        """
        if version >= PostgreSQLVersions.V1_15:
            compression_byte = self.dio.read_byte(stream)
            compression_map = {
                0: CompressionMethod.NONE,
                1: CompressionMethod.RAW,
                2: CompressionMethod.LZ4,
                3: CompressionMethod.ZLIB,
            }
            compression_method = compression_map.get(compression_byte)
            if compression_method is None:
                message = f'Unknown compression method: {compression_byte}'
                raise PgDumpError(message)
        else:
            compression = self.dio.read_int(stream)
            if compression == -1:
                compression_method = CompressionMethod.ZLIB
            elif compression == 0:
                compression_method = CompressionMethod.NONE
            elif 1 <= compression <= 9:
                compression_method = CompressionMethod.RAW
            else:
                message = f'Invalid compression level: {compression}'
                raise PgDumpError(message)

        return compression_method

    def _parse_date(self, stream: Union[BinaryIO, BufferedStreamReader]) -> datetime.datetime:
        """
        Парсинг даты создания из дампа.
        :param stream: поток для чтения
        :return: дата создания
        """
        sec = self.dio.read_int(stream)
        minute = self.dio.read_int(stream)
        hour = self.dio.read_int(stream)
        day = self.dio.read_int(stream)
        month = self.dio.read_int(stream)
        year = self.dio.read_int(stream)
        _isdst = self.dio.read_int(stream)

        try:
            return datetime.datetime(year=year + 1900, month=month + 1, day=day, hour=hour, minute=minute, second=sec)
        except ValueError as error:
            message = f'Invalid creation date: {error}'
            raise PgDumpError(message) from error


class TocParser:
    """Парсер записей оглавления (Table of Contents)."""

    def __init__(self, dio: DumpIO):
        """
        Инициализация парсера TOC.
        :param dio: объект для работы с бинарным I/O
        """
        self.dio = dio

    def parse(self, stream: Union[BinaryIO, BufferedStreamReader], version: Version) -> list[TocEntry]:
        """
        Парсинг всех записей TOC.
        :param stream: поток для чтения
        :param version: версия формата дампа
        :return: список записей TOC
        """
        num_entries = self.dio.read_int(stream)
        return [self._parse_entry(stream, version) for _ in range(num_entries)]

    def _parse_entry(self, stream: Union[BinaryIO, BufferedStreamReader], version: Version) -> TocEntry:
        """
        Парсинг одной записи TOC.
        :param stream: поток для чтения
        :param version: версия формата дампа
        :return: запись TOC
        """
        dump_id = self.dio.read_int(stream)
        had_dumper = bool(self.dio.read_int(stream))

        table_oid = self.dio.read_string(stream)
        oid = self.dio.read_string(stream)
        tag = self.dio.read_string(stream)
        desc = self.dio.read_string(stream)

        section_idx = self.dio.read_int(stream)
        section = self._parse_section(section_idx)

        defn = self.dio.read_string(stream)
        drop_stmt = self.dio.read_string(stream)
        copy_stmt = self.dio.read_string(stream)
        namespace = self.dio.read_string(stream)
        tablespace = self.dio.read_string(stream)

        tableam = None
        if version >= PostgreSQLVersions.V1_14:
            tableam = self.dio.read_string(stream)

        owner = self.dio.read_string(stream)
        with_oids = self.dio.read_string(stream)

        dependencies = self._parse_dependencies(stream)

        data_state = self.dio.read_byte(stream)
        offset = self.dio.read_offset(stream)

        return TocEntry(
            dump_id=dump_id,
            had_dumper=had_dumper,
            tag=tag or None,
            desc=desc or None,
            section=section,
            defn=defn or None,
            copy_stmt=copy_stmt or None,
            drop_stmt=drop_stmt or None,
            namespace=namespace or None,
            tablespace=tablespace or None,
            tableam=tableam,
            data_state=data_state,
            owner=owner or None,
            offset=offset,
            with_oids=with_oids or None,
            table_oid=table_oid or None,
            oid=oid or None,
            dependencies=dependencies,
        )

    def _parse_section(self, section_idx: int) -> SectionType:
        """
        Парсинг типа секции по индексу.
        :param section_idx: индекс секции
        :return: тип секции
        """
        section_map = {
            1: SectionType.PRE_DATA,
            2: SectionType.DATA,
            3: SectionType.POST_DATA,
            4: SectionType.NONE,
        }
        return section_map.get(section_idx, SectionType.NONE)

    def _parse_dependencies(self, stream: Union[BinaryIO, BufferedStreamReader]) -> list[DumpId]:
        """
        Парсинг списка зависимостей.
        :param stream: поток для чтения
        :return: список ID зависимостей
        """
        dependencies = []
        while True:
            dep_str = self.dio.read_string(stream)
            if not dep_str:
                break
            try:
                dependencies.append(int(dep_str))
            except ValueError:
                pass
        return dependencies


class DataBlockProcessor:
    """Обработчик блоков данных с потоковой обработкой decompress→process→compress."""

    def __init__(self, dio: DumpIO, processor: PgStageParser):
        """
        :param dio: объект для работы с бинарным I/O
        :param processor: процессор данных (PgStageParser)
        """
        self.dio = dio
        self.processor = processor

    def process_block(
        self,
        input_stream: Union[BinaryIO, BufferedStreamReader],
        output_stream: BinaryIO,
        dump_id: DumpId,
        compression: CompressionMethod,
    ) -> None:
        """
        Обработка одного блока данных.
        :param input_stream: входной поток
        :param output_stream: выходной поток
        :param dump_id: ID записи дампа
        :param compression: метод сжатия
        """
        if compression in (CompressionMethod.ZLIB, CompressionMethod.RAW):
            self._process_compressed_block_streaming(input_stream, output_stream, dump_id)
        else:
            self._process_uncompressed_block(input_stream, output_stream, dump_id)

    def _process_compressed_block_streaming(
        self,
        input_stream: Union[BinaryIO, BufferedStreamReader],
        output_stream: BinaryIO,
        dump_id: DumpId,
    ) -> None:
        """
        Потоковая обработка сжатого блока: decompress→process lines→compress
        в одном проходе без промежуточных файлов. Память ограничена размером чанка.

        :param input_stream: входной поток
        :param output_stream: выходной поток
        :param dump_id: ID записи дампа
        """
        output_stream.write(BlockType.DATA)
        output_stream.write(self.dio.write_int(dump_id))

        decompressor = zlib.decompressobj()
        compressor = zlib.compressobj(level=Constants.COMPRESSION_LEVEL)
        line_tail = b''

        while True:
            chunk_size = self.dio.read_int(input_stream)
            if chunk_size == 0:
                break

            if chunk_size > Constants.MAX_CHUNK_SIZE:
                message = f'Chunk size too large: {chunk_size}'
                raise PgDumpError(message)

            compressed_data = input_stream.read(chunk_size)
            if len(compressed_data) != chunk_size:
                message = f'Expected {chunk_size} bytes, got {len(compressed_data)}'
                raise PgDumpError(message)

            try:
                decompressed = decompressor.decompress(compressed_data)
            except zlib.error as error:
                message = f'Decompression error: {error}'
                raise PgDumpError(message) from error

            if decompressed:
                line_tail = self._process_and_compress(
                    line_tail + decompressed, compressor, output_stream, is_final=False,
                )

        try:
            final_decomp = decompressor.flush()
        except zlib.error as error:
            message = f'Final decompression error: {error}'
            raise PgDumpError(message) from error

        if final_decomp:
            line_tail = self._process_and_compress(
                line_tail + final_decomp, compressor, output_stream, is_final=False,
            )

        if line_tail:
            self._compress_and_write_chunk(
                self._process_line_bytes(line_tail, has_newline=False),
                compressor, output_stream,
            )

        final_compressed = compressor.flush()
        if final_compressed:
            output_stream.write(self.dio.write_int(len(final_compressed)))
            output_stream.write(final_compressed)

        output_stream.write(self.dio.write_int(0))
        output_stream.flush()

    def _process_and_compress(
        self,
        data: bytes,
        compressor,
        output_stream: BinaryIO,
        *,
        is_final: bool,
    ) -> bytes:
        """
        Обработать строки в данных и сжать результат.
        Возвращает незавершённый хвост (неполная строка без \\n).

        :param data: данные для обработки (могут содержать неполную строку в конце)
        :param compressor: zlib compressor object
        :param output_stream: выходной поток
        :param is_final: True если это последние данные
        :return: хвост без \\n (неполная строка)
        """
        last_newline = data.rfind(b'\n')
        if last_newline == -1:
            if is_final:
                self._compress_and_write_chunk(
                    self._process_line_bytes(data, has_newline=False),
                    compressor, output_stream,
                )
                return b''
            return data

        complete = data[:last_newline + 1]
        tail = data[last_newline + 1:]

        processed = self._process_complete_lines(complete)
        self._compress_and_write_chunk(processed, compressor, output_stream)

        return tail

    def _process_complete_lines(self, data: bytes) -> bytes:
        """
        Обработать блок завершённых строк (каждая заканчивается \\n).
        :param data: данные с завершёнными строками
        :return: обработанные данные
        """
        result_parts = []
        start = 0
        while start < len(data):
            newline_pos = data.find(b'\n', start)
            if newline_pos == -1:
                break
            line_bytes = data[start:newline_pos]
            start = newline_pos + 1
            result_parts.append(self._process_line_bytes(line_bytes, has_newline=True))
        return b''.join(result_parts)

    def _process_line_bytes(self, line_bytes: bytes, *, has_newline: bool) -> bytes:
        """
        Обработать одну строку через обфускатор.
        :param line_bytes: байты строки (без \\n)
        :param has_newline: добавить \\n в конец результата
        :return: обработанные байты
        """
        if not line_bytes:
            return b'\n' if has_newline else b''

        try:
            line = line_bytes.decode('utf-8')
        except UnicodeDecodeError:
            return line_bytes + (b'\n' if has_newline else b'')

        processed = self.processor.process_line(line)
        if isinstance(processed, str):
            result = processed.encode('utf-8') if processed != line else line_bytes
        else:
            result = line_bytes
        return result + (b'\n' if has_newline else b'')

    def _compress_and_write_chunk(self, data: bytes, compressor, output_stream: BinaryIO) -> None:
        """
        Сжать данные и записать как чанк в выходной поток.
        :param data: данные для сжатия
        :param compressor: zlib compressor object
        :param output_stream: выходной поток
        """
        if not data:
            return
        compressed = compressor.compress(data)
        if compressed:
            output_stream.write(self.dio.write_int(len(compressed)))
            output_stream.write(compressed)

    def _process_uncompressed_block(
        self,
        input_stream: Union[BinaryIO, BufferedStreamReader],
        output_stream: BinaryIO,
        dump_id: DumpId,
    ) -> None:
        """
        Потоковая обработка несжатого блока данных.
        :param input_stream: входной поток
        :param output_stream: выходной поток
        :param dump_id: ID записи дампа
        """
        output_stream.write(BlockType.DATA)
        output_stream.write(self.dio.write_int(dump_id))

        line_tail = b''
        output_buf = bytearray()

        while True:
            size = self.dio.read_int(input_stream)
            if size <= 0:
                break

            remaining = size
            while remaining > 0:
                read_size = min(remaining, Constants.DEFAULT_BUFFER_SIZE)
                data = input_stream.read(read_size)
                if len(data) != read_size:
                    message = f'Expected {read_size} bytes, got {len(data)}'
                    raise PgDumpError(message)
                remaining -= read_size

                chunk = line_tail + data
                last_nl = chunk.rfind(b'\n')
                if last_nl == -1:
                    line_tail = chunk
                    continue

                complete = chunk[:last_nl + 1]
                line_tail = chunk[last_nl + 1:]

                processed = self._process_complete_lines(complete)
                output_buf.extend(processed)

                if len(output_buf) >= Constants.OUTPUT_CHUNK_SIZE:
                    output_stream.write(self.dio.write_int(len(output_buf)))
                    output_stream.write(output_buf)
                    output_buf.clear()

        if line_tail:
            output_buf.extend(self._process_line_bytes(line_tail, has_newline=False))

        if output_buf:
            output_stream.write(self.dio.write_int(len(output_buf)))
            output_stream.write(output_buf)

        output_stream.write(self.dio.write_int(0))
        output_stream.flush()


class DumpProcessor:
    """Главный процессор дампов PostgreSQL с оптимизированной обработкой."""

    def __init__(self, data_parser: DataParser):
        """
        Инициализация процессора дампов.
        :param data_parser: обработчик данных
        """
        self.data_parser = data_parser
        self.dio = DumpIO()

    def process_stream(self, input_stream: BinaryIO, output_stream: BinaryIO) -> None:
        """
        Обработка дампа из входного потока в выходной поток.
        :param input_stream: входной поток
        :param output_stream: выходной поток
        """
        buffered_stream = BufferedStreamReader(input_stream, output_stream)

        buffered_stream.bypass_on()
        dump = self._parse_header_and_toc(buffered_stream)
        buffered_stream.bypass_off()

        self._process_data_blocks(buffered_stream, output_stream, dump)

    def _parse_header_and_toc(self, input_stream: Union[BinaryIO, BufferedStreamReader]) -> Dump:
        """
        Парсинг заголовка и TOC без перехвата исключений.
        BufferedStreamReader автоматически читает данные порциями из потока,
        поэтому мы можем парсить напрямую без предварительного чтения всего в буфер.
        :param input_stream: входной поток (должен быть BufferedStreamReader)
        :return: объект дампа
        """
        header_parser = HeaderParser(self.dio)
        header = header_parser.parse(input_stream)

        toc_parser = TocParser(self.dio)
        toc_entries = toc_parser.parse(input_stream, header.version)

        dump = Dump(header=header, toc_entries=toc_entries)

        return dump

    def _process_data_blocks(
        self,
        input_stream: Union[BinaryIO, BufferedStreamReader],
        output_stream: BinaryIO,
        dump: Dump,
    ) -> None:
        """
        Обработка блоков данных в дампе с прогресс-индикатором.
        :param input_stream: входной поток
        :param output_stream: выходной поток
        :param dump: объект дампа
        """
        dump_comments = {entry.defn for entry in dump.get_comment_entries() if entry.defn}
        for comment in dump_comments:
            with suppress(Exception):
                self.data_parser.parse(comment)

        table_data_entries = list(dump.get_table_data_entries())
        dump_copy_stmts = {entry.dump_id: entry.copy_stmt for entry in table_data_entries if entry.copy_stmt}
        dump_ids = {entry.dump_id for entry in table_data_entries}

        processor = DataBlockProcessor(self.dio, self.data_parser)

        while True:
            try:
                block_type = input_stream.read(1)
                if not block_type:
                    break

                if block_type == BlockType.DATA:
                    dump_id = self.dio.read_int(input_stream)

                    if dump_id in dump_ids:
                        copy_stmt = dump_copy_stmts.get(dump_id)
                        if copy_stmt:
                            with suppress(Exception):
                                self.data_parser.parse(copy_stmt)

                        try:
                            processor.process_block(
                                input_stream,
                                output_stream,
                                dump_id,
                                dump.header.compression_method,
                            )
                        except Exception as error:
                            message = f'Error processing data block {dump_id}: {error}'
                            raise PgDumpError(message) from error
                    else:
                        self._pass_through_block(input_stream, output_stream, block_type, dump_id)

                elif block_type == BlockType.END:
                    output_stream.write(block_type)
                    output_stream.flush()
                    break
                else:
                    output_stream.write(block_type)

            except Exception as error:
                message = f'Error reading block: {error}'
                raise PgDumpError(message) from error

    def _pass_through_block(
        self,
        input_stream: Union[BinaryIO, BufferedStreamReader],
        output_stream: BinaryIO,
        block_type: bytes,
        dump_id: DumpId,
    ) -> None:
        """
        Передача блока без обработки. Корректно обрабатывает формат
        с множеством чанков (size + data), завершённый size=0.
        :param input_stream: входной поток
        :param output_stream: выходной поток
        :param block_type: тип блока
        :param dump_id: ID записи дампа
        """
        output_stream.write(block_type)
        output_stream.write(self.dio.write_int(dump_id))

        while True:
            size = self.dio.read_int(input_stream)
            output_stream.write(self.dio.write_int(size))

            if size <= 0:
                break

            remaining = size
            while remaining > 0:
                read_size = min(remaining, Constants.DEFAULT_BUFFER_SIZE)
                chunk = input_stream.read(read_size)
                if not chunk:
                    message = f'Unexpected EOF while copying block data, {remaining} bytes remaining'
                    raise PgDumpError(message)
                output_stream.write(chunk)
                remaining -= len(chunk)

        output_stream.flush()


class CustomObfuscator(PlainObfuscator):
    """Главный класс для работы с обфускатором."""

    def run(self, *, stdin=None) -> None:
        """
        Метод для запуска обфускации.
        :param stdin: поток, с которого приходит информация в виде бинарных данных
        """
        if not stdin:
            stdin = sys.stdin

        if not isinstance(stdin, io.BufferedReader):
            stdin = stdin.buffer

        dump_processor = DumpProcessor(data_parser=PgStageParser(parser=self._parse_line))
        dump_processor.process_stream(stdin, sys.stdout.buffer)
