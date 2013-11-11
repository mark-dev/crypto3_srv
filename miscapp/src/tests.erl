%%%-------------------------------------------------------------------
%%% @author Mark <>
%%% @copyright (C) 2013, Mark
%%% @doc
%%%
%%% @end
%%% Created : 11 Nov 2013 by Mark <>
%%%-------------------------------------------------------------------
-module(tests).

-compile(export_all).
-include("sslv2.hrl").

do()->
    {ok,S} = gen_tcp:connect("localhost",2222,[binary]),
    {Pub,_Priv} = erl_make_certs_wrap:gen_key(128), 
    Reply = sslv2encoder:encode(#change_keyspec{public_rsa = Pub}), 
    gen_tcp:send(S,Reply),
    receive
	T ->
	    io:format("received ~p ~n",[T])
	end.
