import pytest

from scripts.args_and_kwargs import concatenate_all_args

@pytest.mark.parametrize('arg,output', [
    ((1,2,3,4), '1234'),
    (('hello','my','friend'), 'hellomyfriend')
])
def test_can_read_multipe_arguments(arg, output):

    contatenated_return = concatenate_all_args(*arg)

    assert contatenated_return == output
