import sys
import os


def rawxor(a, b):
    """xor two strings of different length"""
    if len(a) > len(b):
        return [x ^ y for (x, y) in zip(a[:len(b)], b)]
    else:
        return [x ^ y for (x, y) in zip(a, b[:len(a)])]


def decify(hexstring):
    intarray = [int(hexstring[i:i+2], 16)
                for i in range(0, len(hexstring), 2)]
    return intarray


def decixor(a, b):
    return rawxor(decify(a), decify(b))


def hexdecixor(a, b):
    return rawxor(decify(a), b)


def singlexor(a, b):
    return [x ^ b for x in decify(a)]


class MtpBreaker(object):
    """Breaks ascii encoded mtp strings which happen to have spaces"""
    def __init__(self):
        super(MtpBreaker, self).__init__()
        self.cypherfile = self.locate_cypherfile()
        self.cyphertexts = self.parse_cypherfile()
        self.keylength = len(max(self.cyphertexts, key=len))
        self.key = [0]*self.keylength

    def locate_cypherfile(self):
        static_default = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            'crypted.txt')

        if os.path.exists(static_default):
            return static_default
        else:
            print "Couldnt find cyphertext, exiting."
            sys.exit(0)

    def parse_cypherfile(self):
        result = []
        for line in open(self.cypherfile, 'r'):
            result.append(line.rstrip())
        return result

    def add_keyguess(self, cyphertext, bytepos, value):
        """guess a letter and get the resulting key byte"""
        self.key[bytepos] = singlexor(
                            self.cyphertexts[cyphertext],
                            value)[bytepos]

        return self.key[bytepos]

    def keystats(self, printkey=False):
        reco = float(len([x for x in self.key if x > 0]))
        print "Key {0:3.2f}% recovered :)".format(reco / self.keylength*100.0)
        if printkey:
            print self.key

    def decode(self):
        for texts in xrange(len(self.cyphertexts)):
            result = []
            raw = rawxor(self.key, decify(self.cyphertexts[texts]))
            for index in xrange(len(raw)):
                rawchr = raw[index]
                if (self.key[index] != 0):
                    if ((rawchr >= 32 and rawchr <= 90) or
                       (rawchr >= 97 and rawchr <= 122)):
                        result.append(chr(rawchr))
                    else:
                        result.append("_")
                else:
                    result.append("-")
            print ''.join(result)

    def get_key_from_spaces(self, confidence=0.7):
        for base_text in xrange(len(self.cyphertexts)):
            spacecounts = {}
            # print "\n=== Base Message {} ===".format(base_text)

            for challenge_text in xrange(len(self.cyphertexts)):
                result = []

                # Skip xoring base against itself
                if (challenge_text != base_text):

                    # XOR base text with challenge text
                    basexor = decixor(self.cyphertexts[base_text],
                                      self.cyphertexts[challenge_text])

                    for index in xrange(len(basexor)):
                        raw_char = basexor[index]

                        # Look for [a-zA-Z] characters which may indicate space
                        if ((raw_char >= 65 and raw_char <= 90) or
                           (raw_char >= 97 and raw_char <= 122)):
                            result.append(chr(raw_char))
                            # Add possible space to counter
                            spacecounts.setdefault(index, 0)
                            spacecounts[index] += 1
                        else:
                            # if its not alpha, draw a hyphen.
                            result.append("-")
                    # print ''.join(result)

            # look at space counts per base cypher.
            for col, count in spacecounts.iteritems():
                # if over X% of the texts had a possible space, derive key.
                if (count >= len(self.cyphertexts) * confidence):
                    # print "high chance of space at {}".format(col)
                    if not self.key[col]:
                        self.key[col] = singlexor(
                                        self.cyphertexts[base_text],
                                        ord(' '))[col]
                    else:
                        alt = singlexor(
                                self.cyphertexts[base_text],
                                ord(' '))[col]
                        # print "key colision at {} {},{}".format(
                        #        col, self.key[col], alt)


def main():

    breaker = MtpBreaker()
    # get most confident guesses first
    for i in xrange(10, 1, -1):
        breaker.get_key_from_spaces(i/10.0)

    # add manual guesses in form cyphertext, bytepos, value
    # breaker.add_keyguess(0, 27, ord('o'))
    # breaker.add_keyguess(0, 54, ord('e'))
    # breaker.add_keyguess(0, 63, ord('e'))
    # breaker.add_keyguess(0, 64, ord('n'))
    # breaker.add_keyguess(0, 3, ord('r'))
    breaker.add_keyguess(0, 7, ord('r'))
    # breaker.add_keyguess(0, 14, ord('t'))
    breaker.add_keyguess(0, 25, ord('p'))
    # breaker.add_keyguess(0, 26, ord('t'))
    # breaker.add_keyguess(1, 34, ord('y'))
    breaker.add_keyguess(6, 35, ord('n'))
    # breaker.add_keyguess(3, 39, ord('m'))
    # breaker.add_keyguess(3, 55, ord('c'))
    # breaker.add_keyguess(10, 36, ord('s'))
    # breaker.add_keyguess(10, 66, ord('e'))
    # breaker.add_keyguess(10, 69, ord('m'))
    # breaker.add_keyguess(10, 73, ord(' '))
    # breaker.add_keyguess(10, 78, ord(' '))
    # breaker.add_keyguess(10, 82, ord('e'))

    breaker.keystats()
    breaker.decode()


if __name__ == '__main__':
    main()
