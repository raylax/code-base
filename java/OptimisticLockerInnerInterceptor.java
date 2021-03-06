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
                // ?????? version ???
                Object originalVersionVal = versionField.get(et);
                if (originalVersionVal == null) {
                    return;
                }
                String versionColumn = fieldInfo.getColumn();
                // ?????? version ???
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
     * EQ???????????????
     */
    private static class FieldEqFinder {

        /**
         * ?????????
         */
        enum State {
            INIT,
            FIELD_FOUND,
            EQ_FOUND,
            VERSION_VALUE_PRESENT,
            ;
        }

        /**
         * ????????????key
         */
        private String valueKey;
        /**
         * ????????????
         */
        private State state;
        /**
         * ?????????
         */
        private final String fieldName;

        public FieldEqFinder(String fieldName, Wrapper<?> wrapper) {
            this.fieldName = fieldName;
            state = State.INIT;
            find(wrapper);
        }

        /**
         * ???????????????
         */
        public boolean isPresent() {
            return state == State.VERSION_VALUE_PRESENT;
        }

        private boolean find(Wrapper<?> wrapper) {
            Matcher matcher;
            final NormalSegmentList segments = wrapper.getExpression().getNormal();
            for (ISqlSegment segment : segments) {
                // ?????????????????????????????????segment???EQ
                if (state == State.FIELD_FOUND && segment == SqlKeyword.EQ) {
                    this.state = State.EQ_FOUND;
                    // ??????EQ????????????value?????????
                } else if (state == State.EQ_FOUND
                    && (matcher = PARAM_PAIRS_RE.matcher(segment.getSqlSegment())).matches()) {
                    this.valueKey = matcher.group(1);
                    this.state = State.VERSION_VALUE_PRESENT;
                    return true;
                    // ????????????
                } else if (segment instanceof Wrapper) {
                    if (find((Wrapper<?>) segment)) {
                        return true;
                    }
                    // ????????????????????????????????????
                } else if (segment.getSqlSegment().equals(this.fieldName)) {
                    this.state = State.FIELD_FOUND;
                }
            }
            return false;
        }

    }

    /**
     * ??????className??????mapper?????????entity
     * ??????????????????className???entity????????????
     *
     * @param className ??????
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
     * ??????class????????????mapper?????????entity
     *
     * @param clazz ???????????????
     * @return entity class
     */
    private Class<?> findEntityClass(Class<?> clazz) {
        final Type[] genericInterfaces = clazz.getGenericInterfaces();
        Class<?> e = null;
        for (Type genericInterface : genericInterfaces) {
            // ????????????
            if (genericInterface instanceof ParameterizedType) {
                final ParameterizedType parameterizedType = (ParameterizedType) genericInterface;
                if (parameterizedType.getRawType() == BaseMapper.class) {
                    e = (Class<?>) parameterizedType.getActualTypeArguments()[0];
                    break;
                }
            // ????????????
            } else if (genericInterface instanceof Class) {
                // ????????????
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
