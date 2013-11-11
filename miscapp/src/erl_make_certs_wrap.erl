%%%-------------------------------------------------------------------
%%% @author Mark <markdev@debian>
%%% @copyright (C) 2013, Mark
%%% @doc
%%%
%%% @end
%%% Created : 10 Nov 2013 by Mark <markdev@debian>
%%%-------------------------------------------------------------------
-module(erl_make_certs_wrap).

-export([gen_key/1]).

-include_lib("public_key/include/public_key.hrl").

%returns {PublicKey,PrivateKey}
gen_key(Size)->
    #'RSAPrivateKey'{modulus=N,
		     privateExponent=D,
		     publicExponent=E} =  erl_make_certs:gen_rsa(Size),
    {[E,N],[E,N,D]}. 
    
    
