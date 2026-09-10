pub fn is_unix_scheme(url: &str) -> bool {
    url.starts_with("unix://")
}

pub fn parse_prometheus_interval(input: &str) -> u64 {
    const UNITS: [(&str, u64); 7] = [
        ("y", 31_536_000_000),
        ("w", 604_800_000),
        ("d", 86_400_000),
        ("h", 3_600_000),
        ("m", 60_000),
        ("s", 1_000),
        ("ms", 1),
    ];
    let bytes = input.as_bytes();
    let mut offset = 0;
    let mut unit_index = 0;
    let mut total = 0_u64;
    let mut parsed_any = false;
    while offset < bytes.len() {
        while bytes.get(offset).is_some_and(u8::is_ascii_whitespace) {
            offset += 1;
        }
        let number_start = offset;
        while bytes.get(offset).is_some_and(u8::is_ascii_digit) {
            offset += 1;
        }
        if number_start == offset {
            return 0;
        }
        let Ok(number) = input[number_start..offset].parse::<u64>() else {
            return 0;
        };
        let Some((relative, (unit, multiplier))) = UNITS[unit_index..]
            .iter()
            .enumerate()
            .filter(|(_, (unit, _))| input[offset..].starts_with(unit))
            .max_by_key(|(_, (unit, _))| unit.len())
        else {
            return 0;
        };
        unit_index += relative;
        offset += unit.len();
        unit_index += 1;
        let Some(value) = number.checked_mul(*multiplier) else {
            return 0;
        };
        let Some(value) = total.checked_add(value) else {
            return 0;
        };
        total = value;
        parsed_any = true;
    }
    if parsed_any {
        total
    } else {
        0
    }
}

pub fn sanitize_rule_name(name: &str) -> String {
    let mut output = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == ':' {
            output.push(ch);
        } else if !output.ends_with('_') {
            output.push('_');
        }
    }
    output.trim_end_matches('_').to_string()
}

pub fn matches_wildcard(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut p, mut v, mut star, mut retry) = (0, 0, None, 0);
    while v < value.len() {
        if p < pattern.len() && pattern[p] == value[v] {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            while p < pattern.len() && pattern[p] == b'*' {
                p += 1;
            }
            star = Some(p);
            retry = v;
        } else if let Some(after_star) = star {
            retry += 1;
            v = retry;
            p = after_star;
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|ch| *ch == b'*')
}
