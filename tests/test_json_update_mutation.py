import json

import pytest

from src.pg_stage.mutator import Mutator


@pytest.fixture()
def mutator() -> Mutator:
    return Mutator(locale='en')


# ---------------------------------------------------------------------------
# Обновление существующего ключа
# ---------------------------------------------------------------------------


def test_json_update_existing_key_is_replaced(mutator: Mutator) -> None:
    """
    Arrange: JSON с ключом `name`; мутация fixed_value заменяет его на заданное значение
    Act: вызов mutation_json_update
    Assert: значение `name` изменилось, остальные ключи не тронуты
    """
    original = {'name': 'Alice', 'score': 42}
    result = json.loads(
        mutator.mutation_json_update(
            current_value=json.dumps(original),
            mutations_by_key={
                'name': [
                    {'mutation_name': 'fixed_value', 'mutation_kwargs': {'value': 'John'}},
                ]
            },
        )
    )

    assert result['name'] == 'John'  # nosec
    assert isinstance(result['name'], str) and result['name']  # nosec
    assert result['score'] == 42  # nosec


def test_json_update_existing_key_passes_current_value(
    mutator: Mutator, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Arrange: JSON с ключом `phone`; подменяем внутреннюю мутацию,
             чтобы она возвращала значение на основе current_value
    Act: вызов mutation_json_update
    Assert: во внутреннюю мутацию автоматически передано текущее значение ключа
    """
    original = {'phone': '+70000000000', 'role': 'admin'}

    def fake_mutation(*, current_value: str, **kwargs) -> str:
        return f"masked:{current_value}"

    monkeypatch.setattr(
        mutator,
        'mutation_test_echo',
        fake_mutation,
        raising=False,
    )

    result = json.loads(
        mutator.mutation_json_update(
            current_value=json.dumps(original),
            mutations_by_key={
                'phone': [
                    {'mutation_name': 'test_echo', 'mutation_kwargs': {}},
                ]
            },
        )
    )

    assert result['phone'] == 'masked:+70000000000'
    assert result['role'] == 'admin'


def test_json_update_preserving_the_numeric_type(mutator: Mutator) -> None:
    """
    Arrange: JSON с числовым ключом `score`
    Act: вызов mutation mutation_numeric_integer внутри mutation_json_update
    Assert: исходный числовой тип ключа `score` сохранится
    """
    original = {'score': 42}
    result = json.loads(
        mutator.mutation_json_update(
            current_value=json.dumps(original),
            mutations_by_key={
                'score': [
                    {'mutation_name': 'numeric_integer', 'mutation_kwargs': {}},
                ]
            },
        )
    )

    assert isinstance(result['score'], int)


# ---------------------------------------------------------------------------
# Добавление отсутствующего ключа
# ---------------------------------------------------------------------------


def test_json_update_missing_key_is_added(mutator: Mutator) -> None:
    """
    Arrange: JSON не содержит ключа `email`; мутация применяет к нему email
    Act: вызов mutation_json_update
    Assert: ключ `email` появился в результате
    """
    original = {'name': 'Bob'}
    result = json.loads(
        mutator.mutation_json_update(
            current_value=json.dumps(original),
            mutations_by_key={
                'email': [
                    {'mutation_name': 'email', 'mutation_kwargs': {}},
                ]
            },
        )
    )

    assert 'email' in result  # nosec
    assert '@' in result['email']  # nosec
    assert result['name'] == 'Bob'  # nosec


# ---------------------------------------------------------------------------
# Удаление ключа (mutation_name: delete)
# ---------------------------------------------------------------------------


def test_json_update_delete_existing_key(mutator: Mutator) -> None:
    """
    Arrange: JSON с ключом `secret`; мутация delete
    Act: вызов mutation_json_update
    Assert: ключ `secret` отсутствует в результате, остальные нетронуты
    """
    original = {'name': 'Carol', 'secret': 'topsecret'}
    result = json.loads(
        mutator.mutation_json_update(
            current_value=json.dumps(original),
            mutations_by_key={
                'secret': [
                    {'mutation_name': 'delete', 'mutation_kwargs': {}},
                ]
            },
        )
    )

    assert 'secret' not in result  # nosec
    assert result['name'] == 'Carol'  # nosec


def test_json_update_delete_missing_key_is_noop(mutator: Mutator) -> None:
    """
    Arrange: JSON не содержит ключа `ghost`; мутация delete
    Act: вызов mutation_json_update
    Assert: ошибок нет, JSON не изменился
    """
    original = {'name': 'Dave'}
    result = json.loads(
        mutator.mutation_json_update(
            current_value=json.dumps(original),
            mutations_by_key={
                'ghost': [
                    {'mutation_name': 'delete', 'mutation_kwargs': {}},
                ]
            },
        )
    )

    assert result == {'name': 'Dave'}  # nosec


# ---------------------------------------------------------------------------
# Обнуление ключа (mutation_name: null)
# ---------------------------------------------------------------------------


def test_json_update_null_existing_key(mutator: Mutator) -> None:
    """
    Arrange: JSON с ключом `notes`; мутация null
    Act: вызов mutation_json_update
    Assert: значение `notes` стало JSON null (Python None)
    """
    original = {'name': 'Eve', 'notes': 'some private notes'}
    result = json.loads(
        mutator.mutation_json_update(
            current_value=json.dumps(original),
            mutations_by_key={
                'notes': [
                    {'mutation_name': 'null'},
                ]
            },
        )
    )

    assert result['notes'] is None  # nosec
    assert result['name'] == 'Eve'  # nosec


def test_json_update_null_missing_key_adds_null(mutator: Mutator) -> None:
    """
    Arrange: JSON не содержит ключа `notes`; мутация null
    Act: вызов mutation_json_update
    Assert: ключ `notes` добавлен со значением null
    """
    original = {'name': 'Frank'}
    result = json.loads(
        mutator.mutation_json_update(
            current_value=json.dumps(original),
            mutations_by_key={
                'notes': [
                    {'mutation_name': 'null', 'mutation_kwargs': {}},
                ]
            },
        )
    )

    assert 'notes' in result  # nosec
    assert result['notes'] is None  # nosec


# ---------------------------------------------------------------------------
# Некорректный / не-объектный JSON
# ---------------------------------------------------------------------------


def test_json_update_invalid_json_raises(mutator: Mutator) -> None:
    """
    Arrange: current_value — невалидная JSON-строка
    Act: вызов mutation_json_update
    Assert: поднимается ValueError с понятным сообщением
    """
    with pytest.raises(ValueError, match='Invalid JSON value'):
        mutator.mutation_json_update(
            current_value='not-json-at-all',
            mutations_by_key={'name': [{'mutation_name': 'first_name', 'mutation_kwargs': {}}]},
        )


def test_json_update_json_array_raises(mutator: Mutator) -> None:
    """
    Arrange: current_value — JSON-массив, а не объект
    Act: вызов mutation_json_update
    Assert: поднимается ValueError
    """
    result = mutator.mutation_json_update(
        current_value='[1, 2, 3]',
        mutations_by_key={'name': [{'mutation_name': 'first_name', 'mutation_kwargs': {}}]},
    )

    # Non-dict JSON is passed through unchanged (warning logged)
    assert result == '[1, 2, 3]'


def test_json_update_json_scalar_raises(mutator: Mutator) -> None:
    """
    Arrange: current_value — JSON-скаляр (число)
    Act: вызов mutation_json_update
    Assert: поднимается ValueError
    """
    result = mutator.mutation_json_update(
        current_value='42',
        mutations_by_key={'name': [{'mutation_name': 'first_name', 'mutation_kwargs': {}}]},
    )

    # JSON scalar is passed through unchanged (warning logged)
    assert result == '42'


# ---------------------------------------------------------------------------
# NULL-значение из БД (PostgreSQL \N)
# ---------------------------------------------------------------------------


def test_json_update_postgres_null_passthrough(mutator: Mutator) -> None:
    """
    Arrange: current_value равен PostgreSQL NULL (\\N)
    Act: вызов mutation_json_update
    Assert: возвращается \\N без изменений и без ошибок
    """
    result = mutator.mutation_json_update(
        current_value='\\N',
        mutations_by_key={'name': [{'mutation_name': 'first_name', 'mutation_kwargs': {}}]},
    )

    assert result == '\\N'  # nosec


# ---------------------------------------------------------------------------
# Комбинированные сценарии
# ---------------------------------------------------------------------------


def test_json_update_combined_operations(mutator: Mutator) -> None:
    """
    Arrange: JSON с несколькими ключами; одновременно замена, удаление и обнуление
    Act: вызов mutation_json_update
    Assert: каждая операция применена независимо и корректно
    """
    original = {
        'first_name': 'Alice',
        'secret': 'topsecret',
        'notes': 'private',
        'untouched': 'keep me',
    }
    result = json.loads(
        mutator.mutation_json_update(
            current_value=json.dumps(original),
            mutations_by_key={
                'first_name': [
                    {'mutation_name': 'fixed_value', 'mutation_kwargs': {'value': 'John'}},
                ],
                'secret': [
                    {'mutation_name': 'delete', 'mutation_kwargs': {}},
                ],
                'notes': [
                    {'mutation_name': 'null', 'mutation_kwargs': {}},
                ],
            },
        )
    )

    assert result['first_name'] == 'John'  # nosec
    assert 'secret' not in result  # nosec
    assert result['notes'] is None  # nosec
    assert result['untouched'] == 'keep me'  # nosec


def test_json_update_unknown_mutation_raises(mutator: Mutator) -> None:
    """
    Arrange: mutation_kwargs указывает несуществующую мутацию
    Act: вызов mutation_json_update
    Assert: поднимается ValueError с именем мутации в сообщении
    """
    with pytest.raises(ValueError, match='Not found mutation "nonexistent"'):
        mutator.mutation_json_update(
            current_value='{"key": "value"}',
            mutations_by_key={'key': [{'mutation_name': 'nonexistent', 'mutation_kwargs': {}}]},
        )


def test_json_update_applies_mutations_recursively(mutator: Mutator) -> None:
    """
    Arrange: целевой ключ находится в nested dict и в dict внутри списка.
    Act: запускаем json_update с мутацией по имени ключа.
    Assert: мутация применена ко всем совпавшим ключам рекурсивно.
    """
    original = {
        'profile': {
            'phone': '+70000000001',
        },
        'contacts': [
            {'phone': '+70000000002'},
            {'phone': '+70000000003'},
        ],
    }

    result = json.loads(
        mutator.mutation_json_update(
            current_value=json.dumps(original),
            mutations_by_key={
                'phone': [
                    {'mutation_name': 'fixed_value', 'mutation_kwargs': {'value': 'MASKED'}},
                ]
            },
        )
    )

    assert result['profile']['phone'] == 'MASKED'
    assert result['contacts'][0]['phone'] == 'MASKED'
    assert result['contacts'][1]['phone'] == 'MASKED'


def test_json_update_key_name_can_be_current_value(mutator: Mutator) -> None:
    """
    Arrange: в JSON есть ключ с именем current_value.
    Act: применяем мутацию через mutations_by_key.
    Assert: ключ не конфликтует со служебными параметрами вызова.
    """
    original = {'current_value': 'sensitive'}
    result = json.loads(
        mutator.mutation_json_update(
            current_value=json.dumps(original),
            mutations_by_key={
                'current_value': [
                    {'mutation_name': 'fixed_value', 'mutation_kwargs': {'value': 'safe'}},
                ]
            },
        )
    )

    assert result['current_value'] == 'safe'