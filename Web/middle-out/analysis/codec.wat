(module
  (type (;0;) (func))
  (type (;1;) (func (param i32) (result i32)))
  (type (;2;) (func (param i32 i32 i32 i32 i32 i32) (result i32)))
  (type (;3;) (func (param i32 i32 i32 i32 i32) (result i32)))
  (type (;4;) (func (param i32 i32 i32 i32) (result i32)))
  (type (;5;) (func (param i32 i32) (result i32)))
  (func (;0;) (type 0))
  (func (;1;) (type 0)
    i32.const 0
    i32.const 66608
    i32.const 15
    i32.add
    i32.const -16
    i32.and
    i32.store offset=1056)
  (func (;2;) (type 1) (param i32) (result i32)
    (local i32 i32 i32)
    local.get 0
    i32.const 0
    i32.load offset=1056
    local.tee 1
    i32.const 66608
    i32.const 15
    i32.add
    i32.const -16
    i32.and
    local.get 1
    select
    local.tee 2
    i32.add
    i32.const 15
    i32.add
    i32.const -16
    i32.and
    local.tee 3
    local.get 2
    i32.lt_u
    local.get 3
    i32.const 122880
    i32.gt_u
    i32.or
    local.set 0
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.eqz
        br_if 0 (;@2;)
        local.get 0
        br_if 1 (;@1;)
      end
      i32.const 0
      local.get 2
      local.get 3
      local.get 0
      select
      i32.store offset=1056
    end
    i32.const 0
    local.get 2
    local.get 0
    select)
  (func (;3;) (type 2) (param i32 i32 i32 i32 i32 i32) (result i32)
    (local i32 i32 i32 i32 i32)
    global.get 0
    i32.const 16
    i32.sub
    local.tee 6
    global.set 0
    i32.const -1
    local.set 7
    block  ;; label = @1
      local.get 1
      i32.const -4097
      i32.add
      i32.const -3969
      i32.lt_u
      br_if 0 (;@1;)
      local.get 3
      i32.const -33
      i32.add
      i32.const -32
      i32.lt_u
      br_if 0 (;@1;)
      i32.const 0
      local.set 7
      loop  ;; label = @2
        block  ;; label = @3
          block  ;; label = @4
            block  ;; label = @5
              local.get 3
              local.get 7
              i32.eq
              br_if 0 (;@5;)
              local.get 2
              local.get 7
              i32.add
              i32.load8_u
              local.tee 8
              i32.const 223
              i32.and
              i32.const -65
              i32.add
              i32.const 255
              i32.and
              i32.const 26
              i32.lt_u
              br_if 2 (;@3;)
              local.get 8
              i32.const -48
              i32.add
              i32.const 255
              i32.and
              i32.const 10
              i32.lt_u
              br_if 2 (;@3;)
              local.get 8
              i32.const 255
              i32.and
              local.tee 9
              i32.const -32
              i32.add
              local.tee 8
              i32.const 14
              i32.gt_u
              br_if 1 (;@4;)
              i32.const 1
              local.get 8
              i32.shl
              i32.const 24577
              i32.and
              i32.eqz
              br_if 1 (;@4;)
              br 2 (;@3;)
            end
            i32.const -3
            local.set 7
            local.get 3
            i32.const 54
            i32.add
            local.tee 8
            i32.const 65535
            i32.and
            local.get 1
            i32.add
            local.tee 9
            i32.const 16
            i32.add
            local.tee 10
            local.get 5
            i32.gt_u
            br_if 3 (;@1;)
            local.get 4
            i32.const 0
            i32.store offset=12 align=1
            local.get 4
            local.get 1
            i32.store8 offset=11
            local.get 4
            local.get 8
            i32.store8 offset=7
            local.get 4
            i32.const 3
            i32.store16 offset=4 align=1
            local.get 4
            i32.const 1112166480
            i32.store align=1
            local.get 4
            local.get 1
            i32.const 8
            i32.shr_u
            i32.store8 offset=10
            local.get 4
            local.get 1
            i32.const 16
            i32.shr_u
            i32.store8 offset=9
            local.get 4
            local.get 1
            i32.const 24
            i32.shr_u
            i32.store8 offset=8
            local.get 4
            local.get 8
            i32.const 8
            i32.shr_u
            i32.store8 offset=6
            local.get 4
            i32.const 16
            i32.add
            local.tee 5
            i32.const 1047
            i32.const 5
            local.get 2
            local.get 3
            i32.const 255
            i32.and
            call 4
            local.set 7
            local.get 6
            local.get 1
            i32.const 1
            i32.shr_u
            i32.store8 offset=15
            local.get 6
            local.get 1
            i32.const 9
            i32.shr_u
            i32.store8 offset=14
            local.get 4
            local.get 7
            i32.const 16
            i32.add
            local.tee 3
            i32.add
            i32.const 1040
            i32.const 6
            local.get 6
            i32.const 14
            i32.add
            i32.const 2
            call 4
            local.set 8
            local.get 6
            i32.const 8192
            i32.store16 offset=14 align=1
            local.get 4
            local.get 8
            local.get 3
            i32.add
            local.tee 2
            i32.add
            i32.const 1033
            i32.const 6
            local.get 6
            i32.const 14
            i32.add
            i32.const 2
            call 4
            local.set 3
            local.get 6
            i32.const 1
            i32.store8 offset=13
            local.get 7
            local.get 3
            local.get 8
            i32.add
            local.get 4
            local.get 3
            local.get 2
            i32.add
            i32.add
            i32.const 1024
            i32.const 8
            local.get 6
            i32.const 13
            i32.add
            i32.const 1
            call 4
            i32.add
            i32.add
            local.get 4
            i32.add
            i32.const 16
            i32.add
            local.set 7
            loop  ;; label = @5
              block  ;; label = @6
                local.get 1
                br_if 0 (;@6;)
                i32.const 0
                local.set 8
                i32.const -1
                local.set 7
                block  ;; label = @7
                  loop  ;; label = @8
                    local.get 8
                    local.get 9
                    i32.eq
                    br_if 1 (;@7;)
                    local.get 7
                    local.get 5
                    local.get 8
                    i32.add
                    i32.load8_u
                    i32.xor
                    local.set 7
                    i32.const 8
                    local.set 1
                    loop  ;; label = @9
                      block  ;; label = @10
                        local.get 1
                        br_if 0 (;@10;)
                        local.get 8
                        i32.const 1
                        i32.add
                        local.set 8
                        br 2 (;@8;)
                      end
                      i32.const 0
                      local.get 7
                      i32.const 1
                      i32.and
                      i32.sub
                      i32.const -2097792136
                      i32.and
                      local.get 7
                      i32.const 1
                      i32.shr_u
                      i32.xor
                      local.set 7
                      local.get 1
                      i32.const -1
                      i32.add
                      local.set 1
                      br 0 (;@9;)
                    end
                  end
                end
                local.get 4
                local.get 7
                i32.const -1
                i32.xor
                local.tee 7
                i32.const 24
                i32.shl
                local.get 7
                i32.const 8
                i32.shl
                i32.const 16711680
                i32.and
                i32.or
                local.get 7
                i32.const 8
                i32.shr_u
                i32.const 65280
                i32.and
                local.get 7
                i32.const 24
                i32.shr_u
                i32.or
                i32.or
                i32.store offset=12 align=1
                local.get 10
                local.set 7
                br 5 (;@1;)
              end
              local.get 7
              local.get 0
              i32.load8_u
              i32.store8
              local.get 7
              i32.const 1
              i32.add
              local.set 7
              local.get 0
              i32.const 1
              i32.add
              local.set 0
              local.get 1
              i32.const -1
              i32.add
              local.set 1
              br 0 (;@5;)
            end
          end
          local.get 9
          i32.const 95
          i32.eq
          br_if 0 (;@3;)
          i32.const -2
          local.set 7
          br 2 (;@1;)
        end
        local.get 7
        i32.const 1
        i32.add
        local.set 7
        br 0 (;@2;)
      end
    end
    local.get 6
    i32.const 16
    i32.add
    global.set 0
    local.get 7)
  (func (;4;) (type 3) (param i32 i32 i32 i32 i32) (result i32)
    (local i32 i32 i32)
    local.get 0
    local.get 4
    i32.store8 offset=1
    local.get 0
    local.get 2
    i32.store8
    i32.const -2128831035
    local.set 5
    local.get 2
    local.set 6
    local.get 1
    local.set 7
    block  ;; label = @1
      loop  ;; label = @2
        local.get 6
        i32.eqz
        br_if 1 (;@1;)
        local.get 6
        i32.const -1
        i32.add
        local.set 6
        local.get 5
        local.get 7
        i32.load8_u
        i32.xor
        i32.const 16777619
        i32.mul
        local.set 5
        local.get 7
        i32.const 1
        i32.add
        local.set 7
        br 0 (;@2;)
      end
    end
    local.get 0
    local.get 5
    i32.const 24
    i32.shl
    local.get 5
    i32.const 8
    i32.shl
    i32.const 16711680
    i32.and
    i32.or
    local.get 5
    i32.const 8
    i32.shr_u
    i32.const 65280
    i32.and
    local.get 5
    i32.const 24
    i32.shr_u
    i32.or
    i32.or
    i32.store offset=2 align=1
    local.get 0
    i32.const 6
    i32.add
    local.set 7
    local.get 2
    local.set 6
    block  ;; label = @1
      loop  ;; label = @2
        block  ;; label = @3
          local.get 6
          br_if 0 (;@3;)
          local.get 0
          local.get 2
          i32.const 6
          i32.add
          local.tee 7
          i32.add
          local.set 6
          local.get 4
          local.set 1
          loop  ;; label = @4
            local.get 1
            i32.eqz
            br_if 3 (;@1;)
            local.get 6
            local.get 3
            i32.load8_u
            i32.store8
            local.get 6
            i32.const 1
            i32.add
            local.set 6
            local.get 3
            i32.const 1
            i32.add
            local.set 3
            local.get 1
            i32.const -1
            i32.add
            local.set 1
            br 0 (;@4;)
          end
        end
        local.get 7
        local.get 1
        i32.load8_u
        i32.store8
        local.get 7
        i32.const 1
        i32.add
        local.set 7
        local.get 1
        i32.const 1
        i32.add
        local.set 1
        local.get 6
        i32.const -1
        i32.add
        local.set 6
        br 0 (;@2;)
      end
    end
    local.get 7
    local.get 4
    i32.add)
  (func (;5;) (type 4) (param i32 i32 i32 i32) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32)
    i32.const -1
    local.set 4
    block  ;; label = @1
      local.get 1
      i32.const 20
      i32.lt_u
      br_if 0 (;@1;)
      local.get 0
      i32.load8_u
      i32.const 77
      i32.ne
      br_if 0 (;@1;)
      local.get 0
      i32.load8_u offset=1
      i32.const 79
      i32.ne
      br_if 0 (;@1;)
      local.get 0
      i32.load8_u offset=2
      i32.const 90
      i32.ne
      br_if 0 (;@1;)
      local.get 0
      i32.load8_u offset=3
      i32.const 49
      i32.ne
      br_if 0 (;@1;)
      local.get 0
      i32.load8_u offset=4
      i32.const 1
      i32.ne
      br_if 0 (;@1;)
      local.get 0
      i32.load8_u offset=5
      i32.const 1
      i32.ne
      br_if 0 (;@1;)
      local.get 0
      i32.load8_u offset=7
      local.set 5
      local.get 0
      i32.load8_u offset=6
      local.set 6
      local.get 0
      i32.const 8
      i32.add
      call 6
      local.set 7
      local.get 0
      i32.const 12
      i32.add
      call 6
      local.set 8
      i32.const -2
      local.set 4
      local.get 0
      i32.const 16
      i32.add
      call 6
      local.set 9
      local.get 7
      local.get 3
      i32.gt_u
      br_if 0 (;@1;)
      local.get 7
      local.get 6
      i32.const 8
      i32.shl
      local.get 5
      i32.or
      local.tee 10
      i32.const 1
      i32.shl
      i32.ne
      br_if 0 (;@1;)
      local.get 8
      i32.const 20
      i32.add
      local.get 1
      i32.ne
      br_if 0 (;@1;)
      i32.const 20
      local.set 11
      i32.const 0
      local.set 3
      block  ;; label = @2
        loop  ;; label = @3
          local.get 11
          local.get 1
          i32.ge_u
          br_if 1 (;@2;)
          local.get 11
          i32.const 1
          i32.add
          local.set 5
          block  ;; label = @4
            local.get 0
            local.get 11
            i32.add
            i32.load8_u
            local.tee 4
            i32.const 128
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            block  ;; label = @5
              local.get 5
              local.get 1
              i32.lt_u
              br_if 0 (;@5;)
              i32.const -3
              return
            end
            i32.const 0
            local.get 7
            local.get 3
            i32.sub
            local.tee 6
            local.get 6
            local.get 7
            i32.gt_u
            select
            local.set 8
            local.get 11
            i32.const 2
            i32.add
            local.set 11
            local.get 4
            i32.const 127
            i32.and
            local.tee 4
            i32.const 3
            i32.add
            local.set 6
            local.get 3
            local.get 4
            i32.add
            i32.const 3
            i32.add
            local.set 12
            local.get 0
            local.get 5
            i32.add
            i32.load8_u
            local.set 5
            loop  ;; label = @5
              block  ;; label = @6
                local.get 6
                br_if 0 (;@6;)
                local.get 12
                local.set 3
                br 3 (;@3;)
              end
              i32.const -4
              local.set 4
              local.get 8
              i32.eqz
              br_if 4 (;@1;)
              local.get 2
              local.get 10
              local.get 3
              local.get 5
              i32.const 255
              i32.and
              call 7
              br_if 4 (;@1;)
              local.get 8
              i32.const -1
              i32.add
              local.set 8
              local.get 6
              i32.const -1
              i32.add
              local.set 6
              local.get 3
              i32.const 1
              i32.add
              local.set 3
              br 0 (;@5;)
            end
          end
          block  ;; label = @4
            local.get 11
            local.get 4
            i32.add
            i32.const 2
            i32.add
            local.get 1
            i32.le_u
            br_if 0 (;@4;)
            i32.const -5
            return
          end
          i32.const 0
          local.get 7
          local.get 3
          i32.sub
          local.tee 6
          local.get 6
          local.get 7
          i32.gt_u
          select
          local.set 8
          local.get 4
          i32.const 1
          i32.add
          local.set 6
          local.get 3
          local.get 4
          i32.add
          i32.const 1
          i32.add
          local.set 11
          loop  ;; label = @4
            block  ;; label = @5
              local.get 6
              br_if 0 (;@5;)
              local.get 11
              local.set 3
              local.get 5
              local.set 11
              br 2 (;@3;)
            end
            i32.const -6
            local.set 4
            local.get 8
            i32.eqz
            br_if 3 (;@1;)
            local.get 2
            local.get 10
            local.get 3
            local.get 0
            local.get 5
            i32.add
            i32.load8_u
            call 7
            br_if 3 (;@1;)
            local.get 8
            i32.const -1
            i32.add
            local.set 8
            local.get 6
            i32.const -1
            i32.add
            local.set 6
            local.get 3
            i32.const 1
            i32.add
            local.set 3
            local.get 5
            i32.const 1
            i32.add
            local.set 5
            br 0 (;@4;)
          end
        end
      end
      i32.const -7
      local.set 4
      local.get 3
      local.get 7
      i32.ne
      br_if 0 (;@1;)
      local.get 7
      i32.const -7
      local.get 2
      local.get 7
      call 8
      local.get 9
      i32.eq
      select
      local.set 4
    end
    local.get 4)
  (func (;6;) (type 1) (param i32) (result i32)
    local.get 0
    i32.load align=1
    local.tee 0
    i32.const 24
    i32.shl
    local.get 0
    i32.const 8
    i32.shl
    i32.const 16711680
    i32.and
    i32.or
    local.get 0
    i32.const 8
    i32.shr_u
    i32.const 65280
    i32.and
    local.get 0
    i32.const 24
    i32.shr_u
    i32.or
    i32.or)
  (func (;7;) (type 4) (param i32 i32 i32 i32) (result i32)
    (local i32)
    local.get 1
    local.set 4
    block  ;; label = @1
      local.get 2
      i32.eqz
      br_if 0 (;@1;)
      block  ;; label = @2
        local.get 2
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        local.get 2
        i32.const 1
        i32.add
        i32.const 1
        i32.shr_u
        i32.sub
        local.set 4
        br 1 (;@1;)
      end
      local.get 2
      i32.const 1
      i32.shr_u
      local.get 1
      i32.add
      local.set 4
    end
    i32.const -1
    local.set 2
    block  ;; label = @1
      local.get 4
      i32.const 0
      i32.lt_s
      br_if 0 (;@1;)
      local.get 4
      local.get 1
      i32.const 1
      i32.shl
      i32.ge_s
      br_if 0 (;@1;)
      local.get 0
      local.get 4
      i32.add
      local.get 3
      i32.store8
      i32.const 0
      local.set 2
    end
    local.get 2)
  (func (;8;) (type 5) (param i32 i32) (result i32)
    (local i32 i32 i32)
    i32.const 0
    local.set 2
    i32.const -1
    local.set 3
    block  ;; label = @1
      loop  ;; label = @2
        local.get 2
        local.get 1
        i32.eq
        br_if 1 (;@1;)
        local.get 3
        local.get 0
        local.get 2
        i32.add
        i32.load8_u
        i32.xor
        local.set 3
        i32.const 8
        local.set 4
        loop  ;; label = @3
          block  ;; label = @4
            local.get 4
            br_if 0 (;@4;)
            local.get 2
            i32.const 1
            i32.add
            local.set 2
            br 2 (;@2;)
          end
          i32.const 0
          local.get 3
          i32.const 1
          i32.and
          i32.sub
          i32.const -306674912
          i32.and
          local.get 3
          i32.const 1
          i32.shr_u
          i32.xor
          local.set 3
          local.get 4
          i32.const -1
          i32.add
          local.set 4
          br 0 (;@3;)
        end
      end
    end
    local.get 3
    i32.const -1
    i32.xor)
  (func (;9;) (type 2) (param i32 i32 i32 i32 i32 i32) (result i32)
    (local i32)
    i32.const -1
    local.set 6
    block  ;; label = @1
      local.get 1
      i32.const 48
      i32.ne
      br_if 0 (;@1;)
      local.get 3
      i32.const 8
      i32.ne
      br_if 0 (;@1;)
      local.get 5
      i32.const 32
      i32.lt_u
      br_if 0 (;@1;)
      i32.const -2
      local.set 6
      local.get 0
      i32.load8_u
      i32.const 87
      i32.ne
      br_if 0 (;@1;)
      local.get 0
      i32.load8_u offset=1
      i32.const 83
      i32.ne
      br_if 0 (;@1;)
      local.get 0
      i32.load8_u offset=2
      i32.const 67
      i32.ne
      br_if 0 (;@1;)
      local.get 0
      i32.load8_u offset=3
      i32.const 52
      i32.ne
      br_if 0 (;@1;)
      local.get 0
      i32.load8_u offset=4
      i32.const 1
      i32.ne
      br_if 0 (;@1;)
      local.get 0
      i32.load8_u offset=6
      i32.const 32
      i32.ne
      br_if 0 (;@1;)
      local.get 0
      i32.load8_u offset=7
      i32.const 1
      i32.ne
      br_if 0 (;@1;)
      i32.const -3
      local.set 6
      local.get 0
      i32.const 8
      i32.add
      call 6
      local.get 2
      i32.const 8
      call 8
      i32.ne
      br_if 0 (;@1;)
      local.get 0
      i32.const 44
      i32.add
      call 6
      local.get 0
      i32.const 44
      call 8
      i32.ne
      br_if 0 (;@1;)
      local.get 0
      i32.const 12
      i32.add
      local.set 3
      local.get 0
      i32.load8_u offset=5
      local.tee 6
      i32.const 29
      i32.mul
      local.set 1
      i32.const 0
      local.set 0
      loop  ;; label = @2
        local.get 0
        i32.const 32
        i32.eq
        br_if 1 (;@1;)
        local.get 4
        local.get 0
        i32.add
        local.get 2
        local.get 6
        local.get 0
        i32.add
        i32.const 7
        i32.and
        i32.add
        i32.load8_u
        local.get 1
        i32.const 99
        i32.add
        i32.xor
        local.get 3
        local.get 0
        i32.add
        i32.load8_u
        i32.xor
        i32.store8
        local.get 1
        i32.const 17
        i32.add
        local.set 1
        local.get 0
        i32.const 1
        i32.add
        local.set 0
        br 0 (;@2;)
      end
    end
    local.get 6)
  (table (;0;) 1 1 funcref)
  (memory (;0;) 2 2)
  (global (;0;) (mut i32) (i32.const 66608))
  (global (;1;) i32 (i32.const 66608))
  (global (;2;) i32 (i32.const 1024))
  (global (;3;) i32 (i32.const 1060))
  (global (;4;) i32 (i32.const 1024))
  (global (;5;) i32 (i32.const 0))
  (global (;6;) i32 (i32.const 1))
  (export "memory" (memory 0))
  (export "__wasm_call_ctors" (func 0))
  (export "r" (func 1))
  (export "__heap_base" (global 1))
  (export "a" (func 2))
  (export "w" (func 3))
  (export "o" (func 5))
  (export "x" (func 9))
  (export "__indirect_function_table" (table 0))
  (export "__dso_handle" (global 2))
  (export "__data_end" (global 3))
  (export "__global_base" (global 4))
  (export "__memory_base" (global 5))
  (export "__table_base" (global 6))
  (data (;0;) (i32.const 1024) "strategy\00radius\00center\00label\00"))
