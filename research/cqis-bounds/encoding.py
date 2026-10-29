"""Q26 candidate closed static records; no native or proof admission."""
import requant as q
import norm_bounds as n

PREFIX = b'stele/v0.1/cqis/bounds'
CAPACITY = 8192
REQUANT_SCALARS = ('divisor','bias','product_max','quotient_max','output_max',
                   'output_lhs_bound','output_rhs_bound')
NORM_SCALARS = ('unit','S_max','N_max','P','A_max','D_max','MD_max','round_divisor_max',
               'round_bias_max','left_factor_max','sign_lhs','sign_rhs')
REQUANT_ROLES = ('input_lhs','input_rhs','product','bias','quotient_product','division')
NORM_ROLES = ('statistic','numerator','scaled','normal_product','normal_sum','xy',
              'product','bias','quotient_product','division','left')


def unsigned(value,width):
    if (type(width) is not int or width not in (1,2,4,20) or type(value) is not int
            or not 0<=value<2**(8*width)):
        raise ValueError('Capacity')
    return value.to_bytes(width,'little')


def encode(expected):
    if type(expected) is q.Spec:
        c = q.derive(expected)
        tag,scalars,roles,shifts = 1,REQUANT_SCALARS,REQUANT_ROLES,()
        params = unsigned(expected.mantissa,2)+unsigned(expected.shift,1)+unsigned(expected.bits,1)
    elif type(expected) is n.Spec:
        c = n.derive(expected)
        tag,scalars,roles,shifts = 2,NORM_SCALARS,NORM_ROLES,('shift_min','shift_max')
        params = (unsigned(expected.d,2)+bytes((expected.F,expected.G,expected.E))+
                  unsigned(expected.en,4)+unsigned(expected.ed,4))
    else:
        raise ValueError('Spec')
    output = bytearray()
    def append(raw):
        if len(raw)>CAPACITY-len(output):
            raise ValueError('Capacity')
        output.extend(raw)
    def integer(value,width):
        append(unsigned(value,width))
    append(PREFIX);integer(1,4);integer(tag,1);integer(len(params),2);append(params)
    integer(c['prime'],4);integer(8,1);integer(len(scalars),1)
    for name in scalars:
        integer(c[name],20)
    integer(len(shifts),1)
    for name in shifts:
        if not -(2**15)<=c[name]<2**15:
            raise ValueError('Capacity')
        append(c[name].to_bytes(2,'little',signed=True))
    integer(len(roles),1)
    for index,name in enumerate(roles,1):
        record = c['columns'][name]
        integer(index,1);integer(record['count'],4)
        for key in ('left_max','right_max','result_max'):
            integer(record[key],20)
        for key in ('left_caps','right_caps','result_caps'):
            if not 1<=len(record[key])<=20:
                raise ValueError('Capacity')
            integer(len(record[key]),1)
        for key in ('left_caps','right_caps','result_caps'):
            for cap in record[key]:
                integer(cap,1)
        for key in ('carry_caps','lhs','rhs'):
            for value in record[key]:
                integer(value,4)
    return bytes(output)


def validate(expected,raw):
    # Supplied bytes never define expected parameters, roles or field authority.
    canonical = encode(expected)
    if type(raw) is not bytes or len(raw)>CAPACITY or raw!=canonical:
        raise ValueError('Encoding')
