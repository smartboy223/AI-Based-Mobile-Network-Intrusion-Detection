import { md5 } from 'js-md5';

export function md5Hex(input: string): string {
  return md5(input);
}
