package org.cloud.ssm.common;

import java.util.List;
import java.util.Optional;

public interface IBaseService<T> {
	
    Long getCount(T entity);

    Optional<T> getById(Long id);

    List<T> getAll();

    List<T> getAll(int pageNum, int pageSize);

    long save(T entity);

    long deleteById(Long id);
}
