%%%-------------------------------------------------------------------
%%% @author Mark <>
%%% @copyright (C) 2013, Mark
%%% @doc
%%%
%%% @end
%%% Created : 11 Nov 2013 by Mark <>
%%%-------------------------------------------------------------------
-module(ets_mgr).

-export([init/0,
	 is_auth_valid/2,
	 client_connected/3,
	 pid_by_user_id/1,
	 get_all_online_pid/1,
	 get_online_users/0,
	 client_disconnected/3]).

-define(AUTH_ETS,auth_ets).
-define(ONLINE_ETS,online_ets).
-define(PUBLIC_NAMED_ORDERED_SET, [ordered_set,
				   public,
				   named_table,
				   {write_concurrency, true},
				   {read_concurrency, true}]).
init()->
    ets:new(?AUTH_ETS, ?PUBLIC_NAMED_ORDERED_SET),%% {id,login::bitstring(),md5(password) :: binary()}
    ets:new(?ONLINE_ETS,?PUBLIC_NAMED_ORDERED_SET),%% {id,login,pid}
    ets:insert(?AUTH_ETS, {1, <<"mark">>, erlang:md5(<<"mark">>)}),
    ets:insert(?AUTH_ETS, {2, <<"test">>, erlang:md5(<<"test">>)}),
    ets:insert(?AUTH_ETS, {3, <<"arg">>, erlang:md5(<<"arg">>)}).

%returns {true,id} | false
is_auth_valid(Login,Password)->
    case ets:match(?AUTH_ETS,{'$1',Login,Password}) of
	[[ID]] ->
	    {true,ID};
	[] ->
	    false
	end.

get_all_online_pid(ExceptThis) ->
    build_online_pids(ExceptThis).

client_connected(ID,Login,Pid)->
    ets:insert(?ONLINE_ETS,{ID,Login,Pid}).

client_disconnected(ID,_Login,_Pid)->
    ets:delete(?ONLINE_ETS,ID).

pid_by_user_id(ID)->
    case ets:lookup(?ONLINE_ETS,ID) of
	[{ID,_Login,Pid}] -> 
	    {ok,Pid};
	[] ->
	    {error,not_found}
	end.
%%{[id],[logins]}
get_online_users()->
    build_online_tuple(ets:match(?ONLINE_ETS, '$1')).


build_online_tuple(List)->
    build_online_tuple(List,{[],[]}).

build_online_tuple([],Acc)->
    Acc;
build_online_tuple([ [{ID,Login,_Pid}] | Tail],{Ids,Logins}) ->
    build_online_tuple(Tail,{[ID | Ids],[Login | Logins]}).

build_online_pids(ExceptThis)->
    lists:flatten(ets:match(?ONLINE_ETS, {'_','_','$1'})) 
	-- [ExceptThis].
    
