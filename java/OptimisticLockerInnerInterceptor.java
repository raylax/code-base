import com.baomidou.mybatisplus.core.conditions.AbstractWrapper;
import com.baomidou.mybatisplus.core.conditions.ISqlSegment;
import com.baomidou.mybatisplus.core.conditions.Wrapper;
import com.baomidou.mybatisplus.core.conditions.segments.NormalSegmentList;
import com.baomidou.mybatisplus.core.conditions.update.Update;
import com.baomidou.mybatisplus.core.conditions.update.UpdateWrapper;
import com.baomidou.mybatisplus.core.enums.SqlKeyword;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.baomidou.mybatisplus.core.metadata.TableFieldInfo;
import com.baomidou.mybatisplus.core.metadata.TableInfo;
import com.baomidou.mybatisplus.core.metadata.TableInfoHelper;
import com.baomidou.mybatisplus.core.toolkit.Constants;
import com.baomidou.mybatisplus.core.toolkit.ExceptionUtils;
import com.baomidou.mybatisplus.core.toolkit.StringPool;
import com.baomidou.mybatisplus.extension.plugins.inner.InnerInterceptor;
import org.apache.ibatis.executor.Executor;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.mapping.SqlCommandType;

import java.lang.reflect.Field;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class OptimisticLockerInnerInterceptor implements InnerInterceptor {

    private static final String PARAM_UPDATE_METHOD_NAME = "update";
    private static final Map<String, Class<?>> ENTITY_CLASS_CACHE = new ConcurrentHashMap<>();
    private static final Pattern PARAM_PAIRS_RE = Pattern.compile("#\\{ew\\.paramNameValuePairs\\.(" + Constants.WRAPPER_PARAM + "\\d+)\\}");
    private static final String UPDATED_VERSION_VAL_KEY = "#updatedVersionVal#";
    private static final String EW_PARAM_NAME_VALUE_PAIRS_KEY = "ew.paramNameValuePairs";

    private final boolean wrapperMode;

    public OptimisticLockerInnerInterceptor() {
        this(false);
    }

    public OptimisticLockerInnerInterceptor(boolean wrapperMode) {
        this.wrapperMode = wrapperMode;
    }

    @SuppressWarnings("unchecked")
    @Override
    public void beforeUpdate(Executor executor, MappedStatement ms, Object parameter) throws SQLException {
        if (ms.getSqlCommandType() != SqlCommandType.UPDATE) {
            return;
        }
        if (parameter instanceof Map) {
            Map<String, Object> map = (Map<String, Object>) parameter;
            doOptimisticLocker(map, ms.getId());
        }
    }

    protected void doOptimisticLocker(Map<String, Object> map, String msId) {
        //updateById(et), update(et, wrapper);
        Object et = map.getOrDefault(Constants.ENTITY, null);
        if (et != null) {
            // entity
            String methodName = msId.substring(msId.lastIndexOf(StringPool.DOT) + 1);
            TableInfo tableInfo = TableInfoHelper.getTableInfo(et.getClass());
            if (tableInfo == null || !tableInfo.isWithVersion()) {
                return;
            }
            try {
                TableFieldInfo fieldInfo = tableInfo.getVersionFieldInfo();
                Field versionField = fieldInfo.getField();
                // 旧的 version 值
                Object originalVersionVal = versionField.get(et);
                if (originalVersionVal == null) {
                    return;
                }
                String versionColumn = fieldInfo.getColumn();
                // 新的 version 值
                Object updatedVersionVal = this.getUpdatedVersionVal(fieldInfo.getPropertyType(), originalVersionVal);
                if (PARAM_UPDATE_METHOD_NAME.equals(methodName)) {
                    AbstractWrapper<?, ?, ?> aw = (AbstractWrapper<?, ?, ?>) map.getOrDefault(Constants.WRAPPER, null);
                    if (aw == null) {
                        UpdateWrapper<?> uw = new UpdateWrapper<>();
                        uw.eq(versionColumn, originalVersionVal);
                        map.put(Constants.WRAPPER, uw);
                    } else {
                        aw.apply(versionColumn + " = {0}", originalVersionVal);
                    }
                } else {
                    map.put(Constants.MP_OPTLOCK_VERSION_ORIGINAL, originalVersionVal);
                }
                versionField.set(et, updatedVersionVal);
                return;
            } catch (IllegalAccessException e) {
                throw ExceptionUtils.mpe(e);
            }
        }

        // update(LambdaUpdateWrapper) or update(UpdateWrapper)
        if (wrapperMode) {
            setVersionByWrapper(map, msId);
        }
    }

    private void setVersionByWrapper(Map<String, Object> map, String msId) {
        Object ew = map.get(Constants.WRAPPER);
        if (ew instanceof AbstractWrapper && ew instanceof Update) {
            final TableFieldInfo versionField = getVersionField(msId);
            if (versionField == null) {
                return;
            }
            final String versionColumn = versionField.getColumn();
            final FieldEqFinder fieldEqFinder = new FieldEqFinder(versionColumn, (Wrapper<?>) ew);
            if (!fieldEqFinder.isPresent()) {
                return;
            }
            final Map<String, Object> paramNameValuePairs = ((AbstractWrapper<?, ?, ?>) ew).getParamNameValuePairs();
            final Object originalVersionValue = paramNameValuePairs.get(fieldEqFinder.valueKey);
            if (originalVersionValue == null) {
                return;
            }
            final Object updatedVersionVal = getUpdatedVersionVal(originalVersionValue.getClass(), originalVersionValue);
            if (originalVersionValue == updatedVersionVal) {
                return;
            }
            paramNameValuePairs.put(UPDATED_VERSION_VAL_KEY, updatedVersionVal);
            ((Update<?, ?>) ew).setSql(String.format("%s = #{%s.%s}", versionColumn, EW_PARAM_NAME_VALUE_PAIRS_KEY, UPDATED_VERSION_VAL_KEY));
        }
    }

    private TableFieldInfo getVersionField(String msId) {
        final String className = msId.substring(0, msId.lastIndexOf('.'));
        final Class<?> entityClass = getEntityClass(className);
        TableInfo tableInfo = TableInfoHelper.getTableInfo(entityClass);
        return tableInfo.getVersionFieldInfo();
    }

    /**
     * EQ字段查找器
     */
    private static class FieldEqFinder {

        /**
         * 状态机
         */
        enum State {
            INIT,
            FIELD_FOUND,
            EQ_FOUND,
            VERSION_VALUE_PRESENT,
            ;
        }

        /**
         * 字段值的key
         */
        private String valueKey;
        /**
         * 当前状态
         */
        private State state;
        /**
         * 字段名
         */
        private final String fieldName;

        public FieldEqFinder(String fieldName, Wrapper<?> wrapper) {
            this.fieldName = fieldName;
            state = State.INIT;
            find(wrapper);
        }

        /**
         * 是否已存在
         */
        public boolean isPresent() {
            return state == State.VERSION_VALUE_PRESENT;
        }

        private boolean find(Wrapper<?> wrapper) {
            Matcher matcher;
            final NormalSegmentList segments = wrapper.getExpression().getNormal();
            for (ISqlSegment segment : segments) {
                // 如果字段已找到并且当前segment为EQ
                if (state == State.FIELD_FOUND && segment == SqlKeyword.EQ) {
                    this.state = State.EQ_FOUND;
                    // 如果EQ找到并且value已找到
                } else if (state == State.EQ_FOUND
                    && (matcher = PARAM_PAIRS_RE.matcher(segment.getSqlSegment())).matches()) {
                    this.valueKey = matcher.group(1);
                    this.state = State.VERSION_VALUE_PRESENT;
                    return true;
                    // 处理嵌套
                } else if (segment instanceof Wrapper) {
                    if (find((Wrapper<?>) segment)) {
                        return true;
                    }
                    // 判断字段是否是要查找字段
                } else if (segment.getSqlSegment().equals(this.fieldName)) {
                    this.state = State.FIELD_FOUND;
                }
            }
            return false;
        }

    }

    /**
     * 根据className获取mapper对应的entity
     * 此方法会缓存className与entity对应关系
     *
     * @param className 类名
     * @return entity class
     */
    private Class<?> getEntityClass(String className) {
        Class<?> clazz = ENTITY_CLASS_CACHE.get(className);
        if (clazz != null) {
            return clazz;
        }
        try {
            final Class<?> entityClass = findEntityClass(Class.forName(className));
            ENTITY_CLASS_CACHE.put(className, entityClass);
            return entityClass;
        } catch (ClassNotFoundException e) {
            throw ExceptionUtils.mpe(e);
        }
    }

    /**
     * 根据class递归查找mapper对应的entity
     *
     * @param clazz 要查找的类
     * @return entity class
     */
    private Class<?> findEntityClass(Class<?> clazz) {
        final Type[] genericInterfaces = clazz.getGenericInterfaces();
        Class<?> e = null;
        for (Type genericInterface : genericInterfaces) {
            // 处理泛型
            if (genericInterface instanceof ParameterizedType) {
                final ParameterizedType parameterizedType = (ParameterizedType) genericInterface;
                if (parameterizedType.getRawType() == BaseMapper.class) {
                    e = (Class<?>) parameterizedType.getActualTypeArguments()[0];
                    break;
                }
            // 处理继承
            } else if (genericInterface instanceof Class) {
                // 递归查找
                if ((e = findEntityClass(((Class<?>) genericInterface))) != null) {
                    break;
                }
            }
        }
        return e;
    }

    /**
     * This method provides the control for version value.<BR>
     * Returned value type must be the same as original one.
     *
     * @param originalVersionVal ignore
     * @return updated version val
     */
    protected Object getUpdatedVersionVal(Class<?> clazz, Object originalVersionVal) {
        if (long.class.equals(clazz) || Long.class.equals(clazz)) {
            return ((long) originalVersionVal) + 1;
        } else if (int.class.equals(clazz) || Integer.class.equals(clazz)) {
            return ((int) originalVersionVal) + 1;
        } else if (Date.class.equals(clazz)) {
            return new Date();
        } else if (Timestamp.class.equals(clazz)) {
            return new Timestamp(System.currentTimeMillis());
        } else if (LocalDateTime.class.equals(clazz)) {
            return LocalDateTime.now();
        }
        //not supported type, return original val.
        return originalVersionVal;
    }
}
