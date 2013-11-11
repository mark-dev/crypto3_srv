%%
%% %CopyrightBegin%
%%
%% Copyright Ericsson AB 2010. All Rights Reserved.
%%
%% The contents of this file are subject to the Erlang Public License,
%% Version 1.1, (the "License"); you may not use this file except in
%% compliance with the License. You should have received a copy of the
%% Erlang Public License along with this software. If not, it can be
%% retrieved online at http://www.erlang.org/.
%%
%% Software distributed under the License is distributed on an "AS IS"
%% basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
%% the License for the specific language governing rights and limitations
%% under the License.
%%
%% %CopyrightEnd%
%%

%% Create test certificates

-module(erl_make_certs).
-include_lib("public_key/include/public_key.hrl").

-export([gen_rsa/1]).

%%--------------------------------------------------------------------
%% @doc Creates a rsa key (OBS: for testing only)
%% the size are in bytes
%% @spec (::integer()) -> {::atom(), ::binary(), ::opaque()}
%% @end
%%--------------------------------------------------------------------
gen_rsa(Size) when is_integer(Size) ->
    gen_rsa2(Size).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% RSA key generation (OBS: for testing only)
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-define(SMALL_PRIMES, [65537,97,89,83,79,73,71,67,61,59,53,
                 47,43,41,37,31,29,23,19,17,13,11,7,5,3]).

gen_rsa2(Size) ->
    P = prime(Size),
    Q = prime(Size),
    N = P*Q,
    Tot = (P - 1) * (Q - 1),
    [E|_] = lists:dropwhile(fun(Candidate) -> (Tot rem Candidate) == 0 end, ?SMALL_PRIMES),
    {D1,D2} = extended_gcd(E, Tot),
    D = erlang:max(D1,D2),
    case D < E of
        true ->
         gen_rsa2(Size);
        false ->
         {Co1,Co2} = extended_gcd(Q, P),
         Co = erlang:max(Co1,Co2),
         #'RSAPrivateKey'{version = 'two-prime',
                         modulus = N,
                         publicExponent = E,
                         privateExponent = D,
                         prime1 = P,
                         prime2 = Q,
                         exponent1 = D rem (P-1),
                         exponent2 = D rem (Q-1),
                         coefficient = Co
                         }
    end.

%%%%%%% Crypto Math %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
prime(ByteSize) ->
    Rand = odd_rand(ByteSize),
    crypto:erlint(prime_odd(Rand, 0)).

prime_odd(Rand, N) ->
    case is_prime(Rand, 50) of
        true ->
         Rand;
        false ->
         NotPrime = crypto:erlint(Rand),
         prime_odd(crypto:mpint(NotPrime+2), N+1)
    end.

%% see http://en.wikipedia.org/wiki/Fermat_primality_test
is_prime(_, 0) -> true;
is_prime(Candidate, Test) ->
    CoPrime = odd_rand(<<0,0,0,4, 10000:32>>, Candidate),
    case crypto:mod_exp(CoPrime, Candidate, Candidate) of
        CoPrime -> is_prime(Candidate, Test-1);
        _ -> false
    end.

odd_rand(Size) ->
    Min = 1 bsl (Size*8-1),
    Max = (1 bsl (Size*8))-1,
    odd_rand(crypto:mpint(Min), crypto:mpint(Max)).

odd_rand(Min,Max) ->
    Rand = <<Sz:32, _/binary>> = crypto:rand_uniform(Min,Max),
    BitSkip = (Sz+4)*8-1,
    case Rand of
        Odd = <<_:BitSkip, 1:1>> -> Odd;
        Even = <<_:BitSkip, 0:1>> ->
         crypto:mpint(crypto:erlint(Even)+1)
    end.
extended_gcd(A, B) ->
    case A rem B of
        0 ->
         {0, 1};
        N ->
         {X, Y} = extended_gcd(B, N),
         {Y, X-Y*(A div B)}
    end.
